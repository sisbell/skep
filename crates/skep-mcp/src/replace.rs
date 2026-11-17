//! `replace_text`: a text edit of a draft, made through the board's own ops.
//!
//! An agent changes text as "replace this exact text with that"; the board
//! changes a document by position. This module does the work between the
//! two: it reads the draft's content as text, finds the old text in it,
//! trims what the old and the new text share at either end, and replaces
//! the bytes that differ alone — so every byte the edit did not change
//! keeps the identity it had, and a link on it still follows. It is
//! apparatus, as `changes_since` and `fetch` are: it composes calls the
//! adapter already makes (`doc_metadata`, `retrieve_doc_v_span_set`,
//! `retrieve_v`, `insert`, `delete`, `image`, and the shell's `held` and
//! `resolve`), and is no wire op.
//!
//! **The text** ([`Text`]). The draft's content subspace is read whole, in
//! parts of the delivery budget ([`READ_POSITIONS`]), and mapped: each
//! maximal run of per-byte values is a *stretch* of text, its bytes as the
//! board holds them (a run that is not UTF-8 arrives as hex and is text all
//! the same, so a part boundary that cut a character costs nothing), and
//! every other value — an atom, a withheld run, a kind this adapter does not
//! know, each with its width — is a *gap*: it takes positions and is no
//! text. A text byte's content ordinal is its stretch's first ordinal plus
//! its offset in the stretch, so a gap before it moves it by the gap's
//! positions, never by its bytes.
//!
//! **The find.** The old text is sought in the stretches alone, overlapping
//! matches counted: it must stand exactly once (`not_found`, `not_unique`
//! with the count). Where no stretch holds it and the text read past its
//! gaps would, the edit is refused `crosses_atom`, naming the gap: an atom
//! is no text.
//!
//! **The trim** ([`shared`]). The longest start and the longest end the old
//! and the new text share are left where they stand, the start cut back to
//! a character boundary and the end forward to one, so no character is
//! split between kept bytes and new ones; what is left is the edit
//! ([`Edit`]): an ordinal, a width removed, the bytes inserted.
//!
//! **The write.** An edit that only inserts or only removes is ONE commit,
//! typed against the first read's position (`as_of`): it lands whole or the
//! board refuses it. One that does both is TWO, since no op of the wire
//! removes and mints in one commit: the new bytes are inserted directly
//! after the old ones, typed against the first read, then the old ones are
//! removed, typed against the insert's own commit. A refusal of the first
//! leaves nothing. Where the second does not land — another writer's change
//! committed between the two — the insert is undone *by identity*: the
//! draft's image is read, the bytes the insert minted are found wherever
//! they now stand, and they are removed, typed against that read
//! ([`UNDO_TRIES`] times at most, against a draft that keeps moving); the
//! edit then answers the refusal that stopped it, the draft as the other
//! writer left it. Where the undo does not land either, the answer is
//! `partial`, `isError`: it names the new bytes standing (`new_text`) and
//! the old ones not removed (`old_text`), each by ordinal and width, the
//! new ones by their I-address and their commit too, so the agent removes
//! one of the two (SP-8: a refusal made after the first write names what
//! that write left). The two spans stand unanswered in one case alone: a
//! process that ends between the two commits answers nothing, which the
//! catalog tells an agent to read the draft after.
//!
//! **A held line.** `insert` and `delete` are bursts, which the shell holds
//! where the board refuses or cannot take them, and a held line stops every
//! later burst on its draft. The edit leaves none: each line of its own is
//! dropped within the call (`resolve`, `drop`), the board's verdict read
//! off it first, so a stale edit, a refused one and one the board could not
//! take all answer `refused` with nothing standing and nothing queued. Two
//! outcomes of a drop are answered as they are: `kept`, a write whose
//! answer was lost and whose landing the shell's read found, is a write
//! that landed; and a drop the shell refuses — it cannot tell whether the
//! write landed while the board does not answer — leaves the line held, and
//! the answer is `held`, `isError`, naming it.
//!
//! **The answer** ([`Answer`]). Every outcome is one JSON object keyed by
//! `outcome`: `replaced`, `unchanged`, `refused`, `held` or `partial`. A
//! refusal the tool or the board decided is data; one where the shell could
//! not get the board's verdict, a held line and a partial landing are
//! `isError`. The board's refusal of a read passes through as every tool's
//! does.

use serde_json::{json, Map, Value};
use skep_client::address::is_address_text;
use skep_client::board::frames;
use skep_client::search::MAX_DELIVERY_ITEMS;
use skep_shell::{Name, Refusal};

use crate::shell::Backend;

/// The most content positions one read of a draft's text asks.
///
/// It is the board's delivery budget (`MAX_DELIVERY_ITEMS`, wire.md §Content
/// & provenance reads): a draft past it is read in consecutive parts.
pub const READ_POSITIONS: u64 = MAX_DELIVERY_ITEMS;

/// The most content positions of a draft an edit reads.
///
/// An edit reads the draft's whole text before it writes, and this adapter
/// serves one call at a time: a draft past the cap is refused `too_large`
/// before any of its text is read (SP-17). It is sixty-four reads of the
/// delivery budget.
pub const MAX_DRAFT_POSITIONS: u64 = 64 * READ_POSITIONS;

/// The most bytes of new text one edit inserts.
///
/// It is the board's cap on the values one `insert` mints (skep-core's
/// codec, `MAX_INSERT_VALUES`), a byte of text being one value: an edit
/// whose trimmed new text passes it is refused `too_large` before any
/// write, where the board would refuse the frame.
pub const MAX_NEW_BYTES: usize = 1 << 18;

/// The window of the image read an undo makes: the draft's whole content.
///
/// The board clips a region to the arrangement, so one read over it answers
/// every run the draft arranges, whatever its extent; a draft past the
/// board's run budget answers `image_too_large`, and the undo is not made.
const WHOLE_CONTENT: u64 = u64::MAX;

/// How many times an undo is typed afresh against a draft that keeps moving.
pub const UNDO_TRIES: usize = 3;

/// The calls an edit makes, each under the adapter's one session.
///
/// The adapter's backend answers them by the shell's rows, so each write
/// asks the shell's one write door as any tool's does (SP-31); the unit
/// suite answers them from a script.
pub trait Calls {
    /// Sends one frame, a read or a write, as the shell's `op` row does.
    ///
    /// # Errors
    ///
    /// The row's refusal: the board's verdict, or the shell's own.
    fn op(&self, frame: Value) -> Result<Value, Refusal>;

    /// Lists the session's held bursts, as the shell's `held` row does.
    ///
    /// # Errors
    ///
    /// The row's refusal.
    fn held(&self) -> Result<Value, Refusal>;

    /// Drops the held line `held`, as the shell's `resolve` row does.
    ///
    /// # Errors
    ///
    /// The row's refusal, `landing_unread` among them: the shell cannot
    /// tell whether the line's write landed, and drops nothing.
    fn drop_held(&self, held: u64) -> Result<Value, Refusal>;
}

impl Calls for Backend {
    fn op(&self, frame: Value) -> Result<Value, Refusal> {
        self.session_call("op", Map::from_iter([(String::from("frame"), frame)]))
    }

    fn held(&self) -> Result<Value, Refusal> {
        self.session_call("held", Map::new())
    }

    fn drop_held(&self, held: u64) -> Result<Value, Refusal> {
        self.session_call("resolve", Map::from_iter([(String::from("held"), Value::from(held)), (String::from("act"), Value::from("drop"))]))
    }
}

/// An edit's answer: one JSON object, and whether it is `isError`.
#[derive(Debug, Clone, PartialEq)]
pub struct Answer {
    /// The answer, keyed by `outcome`.
    pub value: Value,
    /// Whether the tool result is `isError`.
    ///
    /// It is where the shell could not get the board's verdict on a write,
    /// where a line of the edit's stays held, and where the edit landed in
    /// part.
    pub is_error: bool,
}

impl Answer {
    /// Returns an answer that is data.
    fn data(value: Value) -> Answer {
        Answer { value, is_error: false }
    }

    /// Returns an answer that is `isError`.
    fn error(value: Value) -> Answer {
        Answer { value, is_error: true }
    }
}

/// A stretch of text: per-byte values with no other value between them.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Stretch {
    /// Where its bytes begin in the text.
    at: usize,
    /// How many bytes it holds, a position each.
    len: usize,
    /// The content ordinal of its first byte.
    ordinal: u64,
}

/// A value that is no text, and the positions it takes.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Gap {
    /// The content ordinal of its first position.
    ordinal: u64,
    /// What it is, as its delivery item names it: `atom`, `withheld`, `ref`,
    /// or a kind this adapter does not know.
    kind: String,
}

/// A draft's content as an edit reads it: its text, and where each byte stands.
///
/// The text is the bytes of every per-byte value in arrangement order; the
/// stretches say which runs of them are contiguous and at which ordinals,
/// and the gaps what stands between two stretches. Its invariant, kept by
/// [`Text::push`], the one way it grows: the stretches tile `bytes` in
/// order, none empty, and no two are adjacent in position — a part boundary
/// that split one run leaves one stretch.
#[derive(Debug, Default)]
pub struct Text {
    /// The bytes of every per-byte value, in arrangement order.
    bytes: Vec<u8>,
    /// The stretches, in order.
    stretches: Vec<Stretch>,
    /// The gaps, in order.
    gaps: Vec<Gap>,
    /// How many content positions have been read.
    positions: u64,
    /// Whether the value read last was per-byte text.
    open: bool,
}

/// Where the old text stands in a draft's text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Found {
    /// Exactly once: the content ordinal of its first byte.
    Once(u64),
    /// In no stretch, and across no gap.
    Nowhere,
    /// In no stretch, and once or more across a value that is no text.
    Across {
        /// The ordinal of the first value the match would take in.
        ordinal: u64,
        /// What that value is.
        kind: String,
    },
    /// In more than one place: how many.
    Many(u64),
}

/// A delivery item this adapter cannot count the positions of.
///
/// It is a kind it does not know that carries no `width` it reads: every
/// ordinal past it would be a guess, so the edit is not made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Uncounted {
    /// The item's kind, as the delivery names it.
    pub kind: String,
}

impl Text {
    /// Returns how many content positions the text was read over.
    pub fn positions(&self) -> u64 {
        self.positions
    }

    /// Reads one delivery item into the text, at the next position.
    ///
    /// A `content` or `hex` item is per-byte text and joins the stretch
    /// before it where no gap lies between; an `atom`, an `atom_hex` and a
    /// `ref` are one position, a `withheld` run and a kind this adapter
    /// does not know the `width` they carry (wire.md §Value encodings: a
    /// client counts positions past a kind it does not render).
    ///
    /// # Errors
    ///
    /// [`Uncounted`] where the item is no object of one member, a text
    /// item's value is no string or no hex, or a gap's width does not read.
    pub fn push(&mut self, item: &Value) -> Result<(), Uncounted> {
        let uncounted = |kind: &str| Uncounted { kind: kind.to_string() };
        let Some((kind, value)) = item.as_object().filter(|members| members.len() == 1).and_then(|members| members.iter().next()) else {
            return Err(uncounted("item"));
        };
        match kind.as_str() {
            "content" => self.text(value.as_str().ok_or_else(|| uncounted(kind))?.as_bytes()),
            "hex" => self.text(&value.as_str().and_then(unhex).ok_or_else(|| uncounted(kind))?),
            "atom" | "atom_hex" => self.gap(1, "atom"),
            "ref" => self.gap(1, kind),
            _ => self.gap(natural(&value["width"]).filter(|width| *width > 0).ok_or_else(|| uncounted(kind))?, kind),
        }
        Ok(())
    }

    /// Appends per-byte text at the next position.
    fn text(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        match self.stretches.last_mut().filter(|_| self.open) {
            Some(last) => last.len += bytes.len(),
            None => self.stretches.push(Stretch { at: self.bytes.len(), len: bytes.len(), ordinal: self.positions.saturating_add(1) }),
        }
        self.bytes.extend_from_slice(bytes);
        self.positions = self.positions.saturating_add(bytes.len() as u64);
        self.open = true;
    }

    /// Appends a value that is no text, `width` positions wide.
    fn gap(&mut self, width: u64, kind: &str) {
        self.gaps.push(Gap { ordinal: self.positions.saturating_add(1), kind: kind.to_string() });
        self.positions = self.positions.saturating_add(width);
        self.open = false;
    }

    /// Returns where `old` stands in the text.
    ///
    /// Every place `old`'s bytes stand in the text read past its gaps is
    /// judged, overlapping places among them: one within a stretch is a
    /// match, and one that runs past a stretch's end is no match — the
    /// value there is no text — and is told only where no stretch holds
    /// one. `old` is not empty.
    pub fn find(&self, old: &[u8]) -> Found {
        let (mut within, mut first, mut across) = (0u64, None, None);
        let mut stretches = self.stretches.iter().peekable();
        each_occurrence(&self.bytes, old, |at| {
            // The occurrences ascend, so the stretch holding each is reached
            // by stepping forward; the stretches tile the bytes.
            while stretches.peek().is_some_and(|stretch| stretch.at + stretch.len <= at) {
                stretches.next();
            }
            let Some(stretch) = stretches.peek() else { return };
            if at + old.len() <= stretch.at + stretch.len {
                within += 1;
                first.get_or_insert(stretch.ordinal.saturating_add((at - stretch.at) as u64));
            } else {
                across.get_or_insert(stretch.ordinal.saturating_add(stretch.len as u64));
            }
        });
        match (within, first, across) {
            (1, Some(ordinal), _) => Found::Once(ordinal),
            (0, _, None) => Found::Nowhere,
            (0, _, Some(ordinal)) => {
                let kind = self.gaps.iter().find(|gap| gap.ordinal == ordinal).map_or_else(|| "atom".to_string(), |gap| gap.kind.clone());
                Found::Across { ordinal, kind }
            }
            (many, _, _) => Found::Many(many),
        }
    }
}

/// Calls `found` with every place `needle` stands in `hay`, ascending.
///
/// Overlapping places are each found. The scan is Knuth, Morris and Pratt's,
/// linear in the two lengths whatever the bytes repeat; an empty `needle`
/// stands nowhere.
fn each_occurrence(hay: &[u8], needle: &[u8], mut found: impl FnMut(usize)) {
    if needle.is_empty() || hay.len() < needle.len() {
        return;
    }
    // `fail[i]`: the longest proper prefix of `needle[..=i]` that ends it.
    let mut fail = vec![0usize; needle.len()];
    let mut k = 0;
    for i in 1..needle.len() {
        while k > 0 && needle[i] != needle[k] {
            k = fail[k - 1];
        }
        if needle[i] == needle[k] {
            k += 1;
        }
        fail[i] = k;
    }
    let mut k = 0;
    for (i, byte) in hay.iter().enumerate() {
        while k > 0 && *byte != needle[k] {
            k = fail[k - 1];
        }
        if *byte == needle[k] {
            k += 1;
        }
        if k == needle.len() {
            found(i + 1 - k);
            k = fail[k - 1];
        }
    }
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

/// One edit, placed: where its change begins, what it removes and inserts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edit<'a> {
    /// The content ordinal of the first byte removed, or the one the new
    /// bytes are inserted before where none is.
    pub ordinal: u64,
    /// How many bytes are removed, a position each.
    pub removed: u64,
    /// The bytes inserted in their place.
    pub inserted: &'a str,
}

impl<'a> Edit<'a> {
    /// Returns the edit that makes `old`, standing at `found`, read `new`.
    ///
    /// It is `old` and `new` less what they share at either end
    /// ([`shared`]): where the two are the same text it removes and inserts
    /// nothing.
    pub fn of(found: u64, old: &str, new: &'a str) -> Edit<'a> {
        let (lead, tail) = shared(old, new);
        Edit { ordinal: found.saturating_add(lead as u64), removed: (old.len() - lead - tail) as u64, inserted: &new[lead..new.len() - tail] }
    }

    /// Returns the ordinal the new bytes are inserted at: past the old ones.
    fn after(&self) -> u64 {
        self.ordinal.saturating_add(self.removed)
    }
}

/// Returns a natural as the wire spells it: a decimal string, or a number.
fn natural(v: &Value) -> Option<u64> {
    v.as_str().map_or_else(|| v.as_u64(), |text| text.parse().ok())
}

/// Returns the bytes a hex string spells, where it spells whole bytes.
fn unhex(text: &str) -> Option<Vec<u8>> {
    let digit = |b: u8| char::from(b).to_digit(16).and_then(|d| u8::try_from(d).ok());
    let (pairs, odd) = text.as_bytes().as_chunks::<2>();
    odd.is_empty().then(|| pairs.iter().map(|[hi, lo]| Some(digit(*hi)? << 4 | digit(*lo)?)).collect()).flatten()
}

/// Returns how many content positions a `span_set` answer arranges.
///
/// The answer is `retrieve_doc_v_span_set`'s: the count is the width of its
/// span at the content subspace's first position, `1.1`, and 0 where it
/// names none. `None` for an answer that is no span set, or a width that
/// does not read.
fn content_extent(set: &Value) -> Option<u64> {
    let spans = set["set"].as_array()?;
    match spans.iter().find(|span| span["start"] == "1.1") {
        Some(span) => span["width"].as_str()?.rsplit('.').next()?.parse().ok(),
        None => Some(0),
    }
}

/// Where the bytes an insert minted stand in a draft's image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Placed {
    /// Nowhere: the draft arranges none of them.
    Nowhere,
    /// All of them, in their order, from this content ordinal on.
    Whole(u64),
    /// Some of them, or all of them in pieces.
    Parted,
}

/// Returns where the `width` I-addresses from `addr` stand in `image`.
///
/// `image` is an `image` answer over a draft's whole content, its runs in
/// arrangement order. `None` where it is no such answer, or `addr` is no
/// I-address.
fn placed(image: &Value, addr: &str, width: u64) -> Option<Placed> {
    let split = |address: &str| -> Option<(String, u64)> {
        let (prefix, last) = address.rsplit_once('.')?;
        Some((prefix.to_string(), last.parse().ok()?))
    };
    let (prefix, first) = split(addr)?;
    let end = first.checked_add(width)?;
    // Each piece of the minted bytes a run holds: its ordinal, its first
    // address's last component, its width.
    let (mut pieces, mut ordinal) = (Vec::new(), 1u64);
    for run in image["runs"].as_array()? {
        let (run_prefix, run_first) = split(run["i_start"].as_str()?)?;
        let run_width = natural(&run["width"])?;
        let (lo, hi) = (run_first.max(first), run_first.checked_add(run_width)?.min(end));
        let past = ordinal.checked_add(run_width)?;
        if run_prefix == prefix && lo < hi {
            pieces.push((ordinal + (lo - run_first), lo, hi - lo));
        }
        ordinal = past;
    }
    let Some(&(start, _, _)) = pieces.first() else { return Some(Placed::Nowhere) };
    let (mut next_ordinal, mut next_address) = (start, first);
    for (piece_ordinal, piece_first, piece_width) in pieces {
        if piece_ordinal != next_ordinal || piece_first != next_address {
            return Some(Placed::Parted);
        }
        (next_ordinal, next_address) = (piece_ordinal + piece_width, piece_first + piece_width);
    }
    Some(if next_address == end { Placed::Whole(start) } else { Placed::Parted })
}

/// What one write of an edit answered.
#[derive(Debug)]
enum Wrote {
    /// The board's ack.
    Acked(Value),
    /// The shell holds the write's line.
    Held(Line),
}

/// A held line of the edit's own: its ordinal, and why the shell holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Line {
    /// The ordinal `held` lists it by and `resolve` takes.
    held: u64,
    /// The held answer's cause.
    cause: String,
}

/// What became of a held line of the edit's own.
#[derive(Debug)]
enum Settled {
    /// Dropped: its write did not land, and nothing of it is queued.
    Dropped {
        /// The held cause.
        cause: String,
        /// The board's verdict on the write, where it gave one.
        verdict: Option<Value>,
    },
    /// Its write landed: the shell's read found it, its own answer lost.
    Landed,
    /// The shell would not drop it: the line stands, and may land.
    Standing(Line),
}

/// Sends one write of the edit's, and reads its answer.
///
/// # Errors
///
/// The `op` row's refusal of a write it neither sent to an ack nor held.
fn write(calls: &impl Calls, frame: Value) -> Result<Wrote, Refusal> {
    let answer = calls.op(frame)?;
    Ok(match (answer["resp"].as_str(), answer["held"].as_u64()) {
        (Some("held"), Some(held)) => Wrote::Held(Line { held, cause: answer["cause"].as_str().unwrap_or_default().to_string() }),
        _ => Wrote::Acked(answer),
    })
}

/// Settles a held line of the edit's own, so none is left to stop the draft.
///
/// The board's verdict is read off the line first (`held`): a refused run
/// and a moved document each carry one. Then the line is dropped. A drop
/// answered `kept` found the write landed; one answered `no_such_held`
/// found the line gone, which the shell's own resend alone does, at the
/// write's ack; any other refusal of the drop leaves the line standing.
fn settle(calls: &impl Calls, line: Line) -> Settled {
    let verdict = calls.held().ok().and_then(|lines| lines.as_array()?.iter().find(|row| row["held"] == line.held).map(|row| row["refusal"].clone())).filter(|refusal| refusal["resp"] == "rejected");
    match calls.drop_held(line.held) {
        Ok(dropped) if dropped["kept"] == true => Settled::Landed,
        Ok(_) => Settled::Dropped { cause: line.cause, verdict },
        Err(Refusal::Shell { name, .. }) if name == Name::NO_SUCH_HELD => Settled::Landed,
        Err(_) => Settled::Standing(line),
    }
}

/// Removes the bytes an insert minted, wherever they now stand.
///
/// The draft's whole image is read, the `width` addresses from `addr` found
/// in it, and where they stand whole they are removed, typed against that
/// read; a removal the board refuses as typed against an older state is
/// made again from a fresh read, [`UNDO_TRIES`] times in all. Answers
/// whether nothing of the insert stands: removed, found landed, or arranged
/// nowhere already.
fn undo(calls: &impl Calls, doc: &str, addr: &str, width: u64) -> bool {
    for _ in 0..UNDO_TRIES {
        let Ok(image) = calls.op(frames::image(doc, 1, WHOLE_CONTENT)) else { return false };
        let (Some(as_of), Some(placed)) = (image["as_of"].as_u64(), placed(&image, addr, width)) else { return false };
        let ordinal = match placed {
            Placed::Nowhere => return true,
            Placed::Whole(ordinal) => ordinal,
            Placed::Parted => return false,
        };
        match write(calls, frames::delete(doc, ordinal, width, as_of, None)) {
            Ok(Wrote::Acked(_)) => return true,
            Ok(Wrote::Held(line)) => match settle(calls, line) {
                Settled::Landed => return true,
                Settled::Dropped { verdict: Some(verdict), .. } if verdict["code"] == "arrangement_moved" => {}
                Settled::Dropped { .. } | Settled::Standing(_) => return false,
            },
            Err(_) => return false,
        }
    }
    false
}

/// Returns the answer of an edit that landed.
///
/// `at` is the commit the edit was whole at, and `addr` the first I-address
/// the new bytes were minted at; each is absent where the write that would
/// name it was found landed by the shell's read, its own answer lost.
fn replaced(doc: &str, edit: &Edit<'_>, at: Option<u64>, addr: Option<&str>) -> Answer {
    let mut value = json!({"outcome": "replaced", "doc": doc, "ordinal": edit.ordinal.to_string(), "removed": edit.removed.to_string(), "inserted": edit.inserted.len().to_string()});
    if let Some(at) = at {
        value["at"] = Value::from(at);
    }
    if let Some(addr) = addr {
        value["addr"] = Value::from(addr);
    }
    Answer::data(value)
}

/// Returns the answer of an edit the tool refused: nothing was written.
fn refused(doc: &str, cause: &str, detail: Value) -> Answer {
    let mut value = json!({"outcome": "refused", "cause": cause, "doc": doc});
    if let (Some(members), Value::Object(detail)) = (value.as_object_mut(), detail) {
        members.extend(detail);
    }
    Answer::data(value)
}

/// Returns the answer of an edit a write of which did not land.
///
/// Nothing of the edit stands and no line of it is held. With the board's
/// verdict on the write the answer is data, its cause the verdict's code;
/// without one the shell could not get the write to the board, the cause
/// is the hold's, and the answer is `isError`.
fn refused_write(doc: &str, cause: &str, verdict: Option<Value>) -> Answer {
    match verdict {
        Some(verdict) => {
            let code = verdict["code"].as_str().unwrap_or(cause).to_string();
            refused(doc, &code, json!({"refusal": verdict}))
        }
        None => Answer::error(json!({"outcome": "refused", "cause": cause, "doc": doc})),
    }
}

/// Returns the two spans a two-write edit leaves where it is not whole.
///
/// They are `new_text`, the new bytes, placed directly after the old ones,
/// with the I-address and the commit the insert's ack named where it gave
/// one, and `old_text`, the old bytes — each by its ordinal and width as
/// the insert left them. Which of the two stands is the answer's to say: in
/// a `partial` both do; beside a held line, the one its write would place
/// or remove may or may not.
fn spans(edit: &Edit<'_>, inserted: Option<&Value>) -> Value {
    let mut new = json!({"ordinal": edit.after().to_string(), "width": edit.inserted.len().to_string()});
    if let Some(ack) = inserted {
        new["addr"] = ack["addr"].clone();
        new["at"] = ack["at"].clone();
    }
    json!({"new_text": new, "old_text": {"ordinal": edit.ordinal.to_string(), "width": edit.removed.to_string()}})
}

/// Returns the answer of an edit that landed in part, `isError`.
///
/// The new bytes stand and the old ones were not removed ([`spans`]);
/// `why` says what stopped the removal: a `cause`, and the `refusal` beside
/// it where there is one.
fn partial(doc: &str, edit: &Edit<'_>, inserted: Option<&Value>, why: Value) -> Answer {
    let mut value = json!({"outcome": "partial", "doc": doc});
    if let Some(members) = value.as_object_mut() {
        members.extend(spans(edit, inserted).as_object().cloned().unwrap_or_default());
        members.extend(why.as_object().cloned().unwrap_or_default());
    }
    Answer::error(value)
}

/// Returns the answer of an edit a line of which stays held, `isError`.
///
/// `write` names the write the line is, `insert` or `delete`; `stands` is
/// what a two-write edit leaves beside it ([`spans`]), and null for an edit
/// of one write.
fn held(doc: &str, line: &Line, write: &str, stands: Value) -> Answer {
    let mut value = json!({"outcome": "held", "doc": doc, "held": line.held, "cause": line.cause, "write": write});
    if let (Some(members), Value::Object(stands)) = (value.as_object_mut(), stands) {
        members.extend(stands);
    }
    Answer::error(value)
}

/// Returns the answer where the board's answer to a read is none this
/// adapter reads, `isError`.
///
/// Nothing was written. An answer the adapter cannot read is never taken
/// for a draft, an empty one or a text that holds no match (SP-14).
fn unread(doc: &str, op: &str) -> Answer {
    Answer::error(json!({"outcome": "refused", "cause": "unread", "doc": doc, "op": op}))
}

/// A draft's text as read, and the position the read was made at.
struct Read {
    /// The text.
    text: Text,
    /// The `as_of` of the first read, which the edit's first write is typed
    /// against.
    as_of: u64,
}

/// Reads a draft's content as text, in parts of the delivery budget.
///
/// The extent is read first, and its `as_of` is the position every write is
/// typed against: a change to the draft's arrangement after it — between
/// two of the parts' reads, or after the last — refuses the first write.
///
/// # Errors
///
/// The inner error is the edit's own answer, nothing written: `too_large`
/// for a draft past [`MAX_DRAFT_POSITIONS`], `unknown_item` for a delivery
/// item whose positions cannot be counted, `arrangement_moved` where the
/// parts hold other than the positions the extent named — the draft changed
/// between the reads — and `unread` for an answer that is no extent and no
/// delivery. The outer one is the board's or the shell's refusal of a read.
fn read(calls: &impl Calls, doc: &str) -> Result<Result<Read, Answer>, Refusal> {
    let set = calls.op(frames::span_set(doc))?;
    let (Some(as_of), Some(extent)) = (set["as_of"].as_u64(), content_extent(&set)) else {
        return Ok(Err(unread(doc, "retrieve_doc_v_span_set")));
    };
    if extent > MAX_DRAFT_POSITIONS {
        return Ok(Err(refused(doc, "too_large", json!({"what": "draft", "positions": extent.to_string(), "cap": MAX_DRAFT_POSITIONS.to_string()}))));
    }
    let mut text = Text::default();
    let mut from = 1;
    while from <= extent {
        let width = READ_POSITIONS.min(extent - from + 1);
        let delivery = calls.op(frames::retrieve_v(doc, from, width))?;
        let Some(items) = delivery["items"].as_array() else {
            return Ok(Err(unread(doc, "retrieve_v")));
        };
        for item in items {
            if let Err(Uncounted { kind }) = text.push(item) {
                return Ok(Err(refused(doc, "unknown_item", json!({"kind": kind}))));
            }
        }
        from += width;
    }
    if text.positions() != extent {
        return Ok(Err(refused(doc, "arrangement_moved", json!({"as_of": as_of}))));
    }
    Ok(Ok(Read { text, as_of }))
}

/// Makes an edit of one write: an insert alone, or a removal alone.
///
/// # Errors
///
/// The `op` row's refusal of the write, nothing written.
fn one_write(calls: &impl Calls, doc: &str, edit: &Edit<'_>, as_of: u64) -> Result<Answer, Refusal> {
    let (frame, name) = if edit.inserted.is_empty() {
        (frames::delete(doc, edit.ordinal, edit.removed, as_of, None), "delete")
    } else {
        (frames::insert_text(doc, edit.ordinal, edit.inserted, as_of, None), "insert")
    };
    Ok(match write(calls, frame)? {
        Wrote::Acked(ack) => replaced(doc, edit, ack["at"].as_u64(), ack["addr"].as_str()),
        Wrote::Held(line) => match settle(calls, line) {
            Settled::Landed => replaced(doc, edit, None, None),
            Settled::Dropped { cause, verdict } => refused_write(doc, &cause, verdict),
            Settled::Standing(line) => held(doc, &line, name, Value::Null),
        },
    })
}

/// Makes an edit of two writes: the new bytes inserted, then the old removed.
///
/// The insert is typed against the read (`as_of`) and lands directly after
/// the old bytes; the removal is typed against the insert's own commit, so
/// it lands only where nothing changed the draft between the two. A removal
/// that does not land has the insert undone ([`undo`]), and the edit
/// answers what stopped it; where the undo does not land either, `partial`.
///
/// # Errors
///
/// The `op` row's refusal of the insert, nothing written; or of the
/// removal, where the undo then left nothing of the insert standing.
fn two_writes(calls: &impl Calls, doc: &str, edit: &Edit<'_>, as_of: u64) -> Result<Answer, Refusal> {
    let inserted = match write(calls, frames::insert_text(doc, edit.after(), edit.inserted, as_of, None))? {
        Wrote::Acked(ack) => ack,
        Wrote::Held(line) => {
            return Ok(match settle(calls, line) {
                Settled::Dropped { cause, verdict } => refused_write(doc, &cause, verdict),
                Settled::Landed => partial(doc, edit, None, json!({"cause": "answer_lost"})),
                Settled::Standing(line) => held(doc, &line, "insert", spans(edit, None)),
            })
        }
    };
    let (Some(addr), Some(at)) = (inserted["addr"].as_str(), inserted["at"].as_u64()) else {
        return Ok(partial(doc, edit, None, json!({"cause": "unread", "op": "insert"})));
    };
    let width = edit.inserted.len() as u64;
    Ok(match write(calls, frames::delete(doc, edit.ordinal, edit.removed, at, None)) {
        Ok(Wrote::Acked(ack)) => replaced(doc, edit, ack["at"].as_u64(), Some(addr)),
        Ok(Wrote::Held(line)) => match settle(calls, line) {
            Settled::Landed => replaced(doc, edit, None, Some(addr)),
            Settled::Dropped { cause, verdict } if undo(calls, doc, addr, width) => refused_write(doc, &cause, verdict),
            Settled::Dropped { cause, verdict } => partial(doc, edit, Some(&inserted), json!({"cause": verdict.as_ref().and_then(|v| v["code"].as_str()).unwrap_or(&cause), "refusal": verdict})),
            Settled::Standing(line) => held(doc, &line, "delete", spans(edit, Some(&inserted))),
        },
        Err(refusal) if undo(calls, doc, addr, width) => return Err(refusal),
        Err(refusal) => partial(doc, edit, Some(&inserted), json!({"cause": refusal.name(), "refusal": refusal.to_value()})),
    })
}

/// Answers `replace_text {doc, old, new}`: one text edit of a draft.
///
/// In order: the members are read in their form; the document is asked
/// whether it is published, and a published one is refused before any of
/// its text is read; the draft's text is read ([`read`]); `old` is found in
/// it ([`Text::find`]); the edit is trimmed ([`Edit::of`]); and it is
/// written, one commit or two (the module doc's *The write*). Nothing is
/// written before every refusal a read alone decides (SP-8).
///
/// # Errors
///
/// `malformed_args` naming the member, where `doc` is no address in its one
/// spelling, `old` is no string or is empty, or `new` is no string; the
/// board's verdict on a read, or the shell's refusal of it; and the `op`
/// row's refusal of a write that left nothing standing. Every other outcome
/// is an [`Answer`].
pub fn replace_text(calls: &impl Calls, args: &Map<String, Value>) -> Result<Answer, Refusal> {
    let member = |name: &str| args.get(name).and_then(Value::as_str).ok_or_else(|| Refusal::malformed(name));
    let doc = member("doc").ok().filter(|doc| is_address_text(doc)).ok_or_else(|| Refusal::malformed("doc"))?;
    let old = member("old").ok().filter(|old| !old.is_empty()).ok_or_else(|| Refusal::malformed("old"))?;
    let new = member("new")?;
    let metadata = calls.op(frames::doc_metadata(doc))?;
    match metadata["published"].as_bool() {
        Some(false) => {}
        Some(true) => return Ok(refused(doc, "published", json!({"published": metadata["doc"]}))),
        None => return Ok(unread(doc, "doc_metadata")),
    }
    let Read { text, as_of } = match read(calls, doc)? {
        Ok(read) => read,
        Err(answer) => return Ok(answer),
    };
    let found = match text.find(old.as_bytes()) {
        Found::Once(ordinal) => ordinal,
        Found::Nowhere => return Ok(refused(doc, "not_found", json!({"count": 0, "as_of": as_of}))),
        Found::Many(count) => return Ok(refused(doc, "not_unique", json!({"count": count, "as_of": as_of}))),
        Found::Across { ordinal, kind } => return Ok(refused(doc, "crosses_atom", json!({"ordinal": ordinal.to_string(), "kind": kind, "as_of": as_of}))),
    };
    let edit = Edit::of(found, old, new);
    if edit.inserted.len() > MAX_NEW_BYTES {
        return Ok(refused(doc, "too_large", json!({"what": "new", "bytes": edit.inserted.len().to_string(), "cap": MAX_NEW_BYTES.to_string()})));
    }
    match (edit.removed, edit.inserted.is_empty()) {
        (0, true) => Ok(Answer::data(json!({"outcome": "unchanged", "doc": doc, "ordinal": found.to_string(), "as_of": as_of}))),
        (0, false) | (_, true) => one_write(calls, doc, &edit, as_of),
        (_, false) => two_writes(calls, doc, &edit, as_of),
    }
}

#[cfg(test)]
mod tests;
