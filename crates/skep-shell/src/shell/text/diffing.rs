//! `text.diff`: what changed in a draft, told by identity (skep #1091).
//!
//! A caller that changed a draft asks what it changed before it hands the
//! work on: `text.diff(session, {doc, since, stat?, hunk?})`, the `text`
//! family's fifth call, compares the draft `doc` with `since`, a document
//! whose content the draft holds by identity — a mark (`text.mark`), the
//! version member the draft was staged from, a document it copied from —
//! and answers the lines that went and came as a unified diff does, with
//! what a diff of two texts cannot say: a block moved by a `rearrange` is
//! the same bytes at another place and is shown as moved, and a block
//! deleted and typed again is other bytes that read the same and is said
//! re-typed. The call writes nothing, so it asks no write door: a bare
//! session and a second window make it, and a published `doc` is read as any
//! document is. The plan is `skep_client::text::diff`'s; this module makes
//! its reads, builds the two texts and draws the answer.
//!
//! **The reads.** Two `image` reads over the whole content, one of `since`
//! and one of `doc`, give the pairs: no text is compared to find them and
//! `compare` is not called. The draft is then imaged, read as text and
//! imaged again, and where the two images differ, or the read found the
//! draft changed between its parts, the three are made again —
//! [`DIFF_TRIES`] times at most, then the call is refused
//! `arrangement_moved`. `stat: true` reads no text: one image of each
//! document, and the counts alone.
//!
//! **The mapping.** A publication between the two documents re-mints the
//! draft's words — its shot leaves a draft arranging the member's
//! I-addresses where it arranged its own, and homes a correspondence record
//! for each pair in the draft — so once the draft's last image is read,
//! *both* images are mapped through the records the publications left,
//! read once over the two at every origin among their runs, each in its
//! owner's own account (`skep_client::history::records`, and
//! `mapped_image`, the restore's mapping), and the pairs are those of the
//! mapped images, on every path, `stat` too: words a publication re-minted
//! pair with what they were, whether `since` is a mark made before it or
//! the draft published since `doc` copied from it, whether the draft is the
//! person's or another account's its owner published, and a publication
//! landing between the reads finds both images mapped by the records it
//! made. An origin the session may not read yields no record, and its words
//! pair as read. The caller hands the mapping in ([`diff`]);
//! `Shell::text_diff`'s reads the records under the session the call stands
//! under when it runs.
//!
//! **The text before.** `since` is never read whole. A position the draft
//! still holds is told from the draft's text where it stands
//! (`Identity::sources`), and only the spans the draft holds nowhere are
//! read, by identity: `retrieve_i` of their I-addresses off `since`'s
//! mapped image — a re-minted span's at the member's addresses, which hold
//! the same values — in parts ([`parts`]) no larger than the delivery
//! budget, the wire's list cap and what the dialer's answer cap holds at the
//! room a position takes (`frames::I_ITEM_ROOM`). A read by identity
//! refuses whole where one span lies in a document the session may not
//! read: every gone span of that origin is then told as one withheld value
//! of its width, as a text read tells a withheld run, and the read is made
//! again without them, once for each such origin. A position the board
//! holds no value at is `unread`, never text (SP-14).
//!
//! **The bounds** (SP-17). `since` past [`MAX_DRAFT_POSITIONS`] is refused
//! `too_large` before any text is read, its text being told whole in memory
//! as the draft's is; the draft past it is refused by its own read; and two
//! images that make more pairs than the plan's bound are refused `too_large`
//! too (`skep_client::text::diff::MAX_PAIRS`).
//!
//! **The answer.** One JSON object keyed by `outcome` (`shapes`'
//! `TextDiffed`, `TextDiffUnchanged`, `TextRefused`): `unchanged` where
//! every position of both texts stays; else `diffed`, with `shared`, the
//! positions of the draft that `since` holds too, and `bytes`, the change by
//! identity — each count a decimal string. Where the two share no position
//! and neither is empty, that is the whole answer: nothing of `since` is
//! read, and no row is drawn. Else `lines` counts the lines added, removed
//! and moved, `rows` are the hunks from the one asked on (`rows::diffed`),
//! `next_hunk` the hunk to ask next where the rows stopped before the last,
//! and `notes` say the blocks moved, placed twice and re-typed, and the
//! bytes moved within lines. A `hunk` past the last is refused
//! `no_such_hunk`.
//!
//! **The cost** (SP-23). Three images and one read of the draft's text, as
//! every text call makes, each made again where the draft moved; the
//! records' read, one four-set read per distinct origin among the two
//! images' runs for each `MAX_WIRE_LIST` spans of it and one `read_link` per
//! hit homed in a document of that origin's own account, and the mapping, a
//! walk of each run against the records; one read by identity for each part
//! of the gone spans; and the plan's own cost over the two texts' lines. The
//! call holds the draft's text and the text before, each within
//! [`MAX_DRAFT_POSITIONS`].

use std::collections::BTreeSet;

use serde_json::{json, Value};
use skep_client::address::is_address_text;
use skep_client::board::{frames, paged_image, whole_image, Image};
use skep_client::dial::MAX_ANSWER_BYTES;
use skep_client::text::diff::{Gone, Identity, Note, Source, Unplanned};

use super::super::optional;
use super::rows::{diffed as diffed_rows, line_table, DiffRows, ROWS_CONTEXT_LINES};
use super::{read, refused, unread, Answer, Calls, Read, Text, Tiles, Uncounted, MAX_DRAFT_POSITIONS, READ_POSITIONS, WHOLE_CONTENT};
use crate::attest::MAX_WIRE_LIST;
use crate::refusal::Refusal;

/// How many times the draft is imaged and read before the call gives up.
///
/// A draft whose two images differ, or whose read found it changed, is read
/// again; past the count the call is refused `arrangement_moved`.
const DIFF_TRIES: usize = 3;

/// The mapping a diff applies to its two images before it plans them.
///
/// It is handed `since`'s image and the draft's last, and answers the two
/// mapped — through the records the publications left, each origin's in its
/// owner's account, as `Shell::text_diff`'s does — or the refusal that ends
/// the call (the module doc's *The mapping*).
pub(super) type Mapping<'m> = dyn Fn(&Image, &Image) -> Result<(Image, Image), Refusal> + 'm;

/// What the call is asked: the two documents, and how much of the answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Asked<'a> {
    /// The draft, an address in its one spelling.
    doc: &'a str,
    /// The document the draft is compared with, an address likewise.
    since: &'a str,
    /// Whether the counts alone are asked, no text read.
    stat: bool,
    /// The hunk the rows start at, from 1.
    hunk: u64,
}

impl<'a> Asked<'a> {
    /// Reads `text.diff`'s members off `args`, each in its form.
    ///
    /// `stat` absent is false and `hunk` absent the first, a `null` read as
    /// absent.
    ///
    /// # Errors
    ///
    /// `malformed_args` naming the first member not of its form, in this
    /// order: `doc`, then `since`, where it is no address in its one
    /// spelling; `stat` where it is present and no boolean; `hunk` where it
    /// is present and no whole number from 1.
    pub(super) fn read(args: &'a Value) -> Result<Asked<'a>, Refusal> {
        let address = |member: &str| args[member].as_str().filter(|address| is_address_text(address)).ok_or_else(|| Refusal::malformed(member));
        let (doc, since) = (address("doc")?, address("since")?);
        let stat = optional(args, "stat", Value::as_bool)?.unwrap_or(false);
        let hunk = optional(args, "hunk", |hunk| hunk.as_u64().filter(|hunk| *hunk >= 1))?.unwrap_or(1);
        Ok(Asked { doc, since, stat, hunk })
    }
}

/// Reads the whole image of `of`, and the position it was read at.
///
/// The image is read in pages where `of` holds more runs than one answer
/// carries, each page a call of the `op` row, as one state
/// (`paged_image`): a draft written between two pages is read again from
/// its first, and past the restart bound every page is read as of the last
/// first page's position, the row's `/op-at` form. The position answered is
/// the first page's.
///
/// # Errors
///
/// The inner error is the call's own answer: `unread` naming `image` for an
/// answer that is no whole image. The outer one is the board's or the
/// shell's refusal of the read.
fn image(calls: &impl Calls, doc: &str, of: &str) -> Result<Result<(Image, u64), Answer>, Refusal> {
    let answer = paged_image(&frames::image(of, 1, WHOLE_CONTENT), |frame, at| page(calls, frame, at))?;
    Ok(whole_image(&answer).zip(answer["as_of"].as_u64()).ok_or_else(|| unread(doc, "image")))
}

/// Sends one frame of a paged image through the `op` row.
///
/// The frame goes at the head, or as of `at` in the row's `/op-at` form. The
/// row answers a rejection as the board's refusal; the one a paged read
/// acts on, `page_moved`, is handed back as the document the board sent, so
/// the read begins again where the draft changed under it.
///
/// # Errors
///
/// The row's refusal, every other verdict of the board's among them.
fn page(calls: &impl Calls, frame: &Value, at: Option<u64>) -> Result<Value, Refusal> {
    let sent = match at {
        None => frame.clone(),
        Some(at) => json!({"at": at, "frame": frame}),
    };
    match calls.op(sent) {
        Err(Refusal::Board(refused)) if refused.status == 200 && refused.code == "page_moved" => Ok(refused.body),
        answered => answered,
    }
}

/// The draft as the call reads it: its image, its text, and the position.
struct Now {
    /// The draft's whole image.
    image: Image,
    /// The draft's text; empty where the counts alone are asked.
    text: Text,
    /// The position the image was read at.
    as_of: u64,
}

/// Reads the draft `doc`: its image, and its text unless `stat`.
///
/// The text is read between two images, and stands only where the two are
/// one and hold the positions it was read over; else the three reads are
/// made again (the module doc's *The reads*).
///
/// # Errors
///
/// The inner error is the call's own answer: the text read's (`too_large`,
/// `unknown_item`, `unread`), `unread` naming `image`, and
/// `arrangement_moved` where the draft kept moving. The outer one is the
/// board's or the shell's refusal of a read.
fn read_now(calls: &impl Calls, doc: &str, stat: bool) -> Result<Result<Now, Answer>, Refusal> {
    for _ in 0..DIFF_TRIES {
        let (first, as_of) = match image(calls, doc, doc)? {
            Ok(read) => read,
            Err(answer) => return Ok(Err(answer)),
        };
        if stat {
            return Ok(Ok(Now { image: first, text: Text::default(), as_of }));
        }
        let text = match read(calls, doc)? {
            Ok(Read { text, .. }) => text,
            Err(answer) if answer.value["cause"] == "arrangement_moved" => continue,
            Err(answer) => return Ok(Err(answer)),
        };
        let second = match image(calls, doc, doc)? {
            Ok((second, _)) => second,
            Err(answer) => return Ok(Err(answer)),
        };
        if first == second && text.positions() == first.extent() {
            return Ok(Ok(Now { image: first, text, as_of }));
        }
    }
    Ok(Err(refused(doc, "arrangement_moved", json!({"reads": DIFF_TRIES}))))
}

/// One span a part of the gone read asks: positions of one gone span.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Asking {
    /// The gone span, by index.
    span: usize,
    /// How far into the span the positions asked begin.
    into: u64,
    /// How many positions are asked.
    width: u64,
}

/// Returns the parts the gone spans are read in.
///
/// Each span is read from `read` positions into it on. A part is one
/// `retrieve_i`: at most the delivery budget's positions
/// ([`READ_POSITIONS`]), at most a wire list's spans ([`MAX_WIRE_LIST`]),
/// and no more positions than the dialer's answer cap holds at the room one
/// takes under its span's longest address, its last, so a part's answer of
/// per-byte values is read whole. A span past a part goes on in the next; a
/// span marked in `withheld`, and one read to its end, is in none.
fn parts(gone: &[Gone], read: &[u64], withheld: &[bool]) -> Vec<Vec<Asking>> {
    let budget = MAX_ANSWER_BYTES.saturating_sub(frames::I_DELIVERY_ENVELOPE) as u64;
    let (mut parts, mut part, mut positions, mut bytes) = (Vec::new(), Vec::new(), 0u64, 0u64);
    for (span, gone) in gone.iter().enumerate().filter(|(span, _)| !withheld[*span]) {
        let digits = gone.first.saturating_add(gone.width).to_string().len();
        let room = (frames::I_ITEM_ROOM + gone.prefix.len() + ".".len() + digits) as u64;
        let mut into = read[span];
        while into < gone.width {
            let fits = (READ_POSITIONS - positions).min((budget - bytes) / room);
            if fits == 0 || part.len() == MAX_WIRE_LIST {
                parts.push(std::mem::take(&mut part));
                (positions, bytes) = (0, 0);
                continue;
            }
            let width = fits.min(gone.width - into);
            part.push(Asking { span, into, width });
            (positions, bytes, into) = (positions + width, bytes + width * room, into + width);
        }
    }
    if !part.is_empty() {
        parts.push(part);
    }
    parts
}

/// Returns the document the board refused a read by identity over.
///
/// None where `refusal` is no `withheld` of the board's naming one.
fn withheld_origin(refusal: &Refusal) -> Option<&str> {
    match refusal {
        Refusal::Board(refused) if refused.code == "withheld" => refused.body["site"]["addr"].as_str(),
        _ => None,
    }
}

/// Reads the values of the gone spans by identity, each as a text.
///
/// The spans are read in parts ([`parts`]), each position's value pushed as
/// a text read pushes a delivery item. Where the board refuses a part
/// `withheld`, naming a document, every span of that document's content is
/// told as one withheld value of its width and the parts are made again
/// without them — once for each document, a refusal naming one a second
/// time, or one no span lies in, being the call's.
///
/// # Errors
///
/// The inner error is the call's own answer: `unread` naming `retrieve_i`
/// for an answer that is no delivery of the positions asked, or that holds
/// no value at one of them, and `unknown_item` for a value whose positions
/// cannot be counted. The outer one is the board's or the shell's refusal of
/// a read.
fn read_gone(calls: &impl Calls, doc: &str, gone: &[Gone]) -> Result<Result<Vec<Text>, Answer>, Refusal> {
    let mut texts: Vec<Text> = gone.iter().map(|_| Text::default()).collect();
    let (mut read, mut withheld) = (vec![0u64; gone.len()], vec![false; gone.len()]);
    let mut origins: BTreeSet<String> = BTreeSet::new();
    'again: loop {
        for part in parts(gone, &read, &withheld) {
            let starts: Vec<String> = part.iter().map(|asking| format!("{}.{}", gone[asking.span].prefix, gone[asking.span].first.saturating_add(asking.into))).collect();
            let spans: Vec<(&str, u64)> = starts.iter().zip(&part).map(|(start, asking)| (start.as_str(), asking.width)).collect();
            let delivery = match calls.op(frames::retrieve_i(&spans)) {
                Ok(delivery) => delivery,
                Err(refusal) => {
                    let Some(origin) = withheld_origin(&refusal).filter(|origin| !origins.contains(*origin)).map(str::to_string) else { return Err(refusal) };
                    let content = format!("{origin}.0.1");
                    let of_origin: Vec<usize> = (0..gone.len()).filter(|span| gone[*span].prefix == content).collect();
                    if of_origin.is_empty() {
                        return Err(refusal);
                    }
                    for span in of_origin {
                        withheld[span] = true;
                        texts[span] = Text::default();
                        texts[span].gap(gone[span].width, "withheld");
                    }
                    origins.insert(origin);
                    continue 'again;
                }
            };
            let asked: u64 = part.iter().map(|asking| asking.width).sum();
            let Some(items) = delivery["items"].as_array().filter(|items| items.len() as u64 == asked) else {
                return Ok(Err(unread(doc, "retrieve_i")));
            };
            let mut items = items.iter();
            for asking in &part {
                for item in items.by_ref().take(asking.width as usize) {
                    let value = &item["value"];
                    if value.is_null() {
                        return Ok(Err(unread(doc, "retrieve_i")));
                    }
                    if let Err(Uncounted { kind }) = texts[asking.span].push(value) {
                        return Ok(Err(refused(doc, "unknown_item", json!({"kind": kind}))));
                    }
                }
                read[asking.span] = asking.into + asking.width;
                // One value a position: a value of another width is no
                // answer to the positions asked.
                if texts[asking.span].positions() != read[asking.span] {
                    return Ok(Err(unread(doc, "retrieve_i")));
                }
            }
        }
        return Ok(Ok(texts));
    }
}

/// Returns the text before, told from the draft's text and the gone values.
///
/// Each stretch of it is the positions of `now` it stands at, or the gone
/// span's values, in order (`Identity::sources`).
fn text_before(identity: &Identity, now: &Text, gone: &[Text]) -> Text {
    let standing = Tiles::of(now);
    let gone: Vec<Tiles<'_>> = gone.iter().map(Tiles::of).collect();
    let mut before = Text::default();
    for stretch in identity.sources() {
        match stretch.source {
            Source::Now(at) => standing.copy(at, at.saturating_add(stretch.width), &mut before),
            Source::Gone(span) => {
                if let Some(values) = gone.get(span) {
                    values.copy(1, stretch.width.saturating_add(1), &mut before);
                }
            }
        }
    }
    before
}

/// Returns a note as the answer spells it.
fn note(note: &Note) -> Value {
    let lines = |kind: &str, before: (u64, u64), now: (u64, u64)| json!({"kind": kind, "before": [before.0, before.1], "now": [now.0, now.1]});
    match *note {
        Note::Moved { before, now } => lines("moved", before, now),
        Note::PlacedTwice { before, now } => lines("placed_twice", before, now),
        Note::Retyped { before, now } => lines("retyped", before, now),
        Note::MovedWithinLines { bytes } => json!({"kind": "moved_within_lines", "bytes": bytes.to_string()}),
    }
}

/// Makes the diff `asked` through `calls`, its two images mapped by `map`.
///
/// In order: `since` is imaged, and refused where its text would pass the
/// cap; the draft is imaged and read ([`read_now`]); the two images are
/// mapped, `map` called once with `since`'s and the draft's last (the
/// module doc's *The mapping*); the identity is planned over what it
/// answers, and the counts answered where they are the whole answer —
/// nothing changed, the counts alone asked, or nothing shared; the gone
/// spans are read by identity ([`read_gone`]); the text before is told
/// ([`text_before`]); and the lines are planned and their rows drawn.
/// Nothing is written.
///
/// # Errors
///
/// The board's verdict on a read, or the shell's refusal of it; `map`'s
/// refusal. Every other outcome is an [`Answer`].
pub(super) fn diff(calls: &impl Calls, asked: &Asked<'_>, map: &Mapping<'_>) -> Result<Answer, Refusal> {
    let Asked { doc, since, stat, hunk } = *asked;
    let before = match image(calls, doc, since)? {
        Ok((before, _)) => before,
        Err(answer) => return Ok(answer),
    };
    if !stat && before.extent() > MAX_DRAFT_POSITIONS {
        return Ok(refused(doc, "too_large", json!({"what": "since", "positions": before.extent().to_string(), "cap": MAX_DRAFT_POSITIONS.to_string()})));
    }
    let Now { image: now, text, as_of } = match read_now(calls, doc, stat)? {
        Ok(now) => now,
        Err(answer) => return Ok(answer),
    };
    let (before, now) = map(&before, &now)?;
    let identity = match Identity::of(&before, &now) {
        Ok(identity) => identity,
        Err(Unplanned { pairs }) => return Ok(refused(doc, "too_large", json!({"what": "pairs", "pairs": pairs.to_string(), "cap": skep_client::text::diff::MAX_PAIRS.to_string()}))),
    };
    if identity.unchanged() {
        return Ok(Answer::data(json!({"outcome": "unchanged", "doc": doc, "since": since, "as_of": as_of})));
    }
    let bytes = identity.bytes();
    let mut value = json!({
        "outcome": "diffed", "doc": doc, "since": since, "as_of": as_of, "shared": identity.shared().to_string(),
        "bytes": {"new": bytes.new.to_string(), "gone": bytes.gone.to_string(), "moved": bytes.moved.to_string()},
    });
    let apart = identity.shared() == 0 && before.extent() > 0 && now.extent() > 0;
    if stat || apart {
        return Ok(Answer::data(value));
    }
    let gone = match read_gone(calls, doc, identity.gone())? {
        Ok(gone) => gone,
        Err(answer) => return Ok(answer),
    };
    let was = text_before(&identity, &text, &gone);
    let plan = identity.lines(&line_table(&was, false), &line_table(&text, true), ROWS_CONTEXT_LINES);
    let hunks = plan.hunks.len() as u64;
    if hunk > hunks.max(1) {
        return Ok(refused(doc, "no_such_hunk", json!({"hunk": hunk, "count": hunks})));
    }
    let DiffRows { rows, masked, next_hunk } = diffed_rows(&was, &text, &plan, (hunk - 1) as usize);
    value["lines"] = json!({"added": plan.counts.added.to_string(), "removed": plan.counts.removed.to_string(), "moved": plan.counts.moved.to_string()});
    value["rows"] = json!(rows);
    if !plan.notes.is_empty() {
        value["notes"] = Value::Array(plan.notes.iter().map(note).collect());
    }
    if masked {
        value["masked"] = Value::Bool(true);
    }
    if let Some(next) = next_hunk {
        value["next_hunk"] = Value::from(next);
    }
    Ok(Answer::data(value))
}

#[cfg(test)]
mod tests;
