//! The unit suite of `text.diff`.
//!
//! The call is made against a board that answers from modelled texts
//! ([`Board`]): each text its bytes with the I-address each stands at, so a
//! line picked out of a text keeps its bytes' identity and text typed mints
//! its own. The board answers the images, the draft's extent and text and
//! the reads by identity as the wire spells them, and keeps every frame, so
//! a cell holds the reads the call makes, their order, and what it draws of
//! them. The row itself and a real board's marks run against the daemon in
//! `shell/tests/text.rs`.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;

use skep_client::halt::Refused;

use super::super::tests::DOC;
use super::*;

/// The document every modelled diff compares the draft with.
const SINCE: &str = "1.0.1.0.65";

/// Another account's draft, whose content a modelled session may not read.
const OTHER: &str = "1.0.2.0.9";

/// The position the modelled board answers every read at.
const AT: u64 = 40;

/// A text: each byte with the document that minted it and its ordinal.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct Doc(Vec<(&'static str, u64, u8)>);

impl Doc {
    /// Returns `text` typed afresh: minted in `origin` from `first` on.
    fn typed(origin: &'static str, first: u64, text: &str) -> Doc {
        Doc(text.bytes().enumerate().map(|(k, byte)| (origin, first + k as u64, byte)).collect())
    }

    /// Returns the lines numbered `lines`, from 1, one after another.
    ///
    /// Each byte keeps its address.
    fn pick(&self, lines: &[usize]) -> Doc {
        let (mut ranges, mut start) = (Vec::new(), 0);
        for (at, cell) in self.0.iter().enumerate() {
            if cell.2 == b'\n' {
                ranges.push(start..at + 1);
                start = at + 1;
            }
        }
        ranges.push(start..self.0.len());
        Doc(lines.iter().flat_map(|line| self.0[ranges[line - 1].clone()].iter().copied()).collect())
    }

    /// Returns the text followed by `next`.
    fn then(mut self, next: &Doc) -> Doc {
        self.0.extend(next.0.iter().copied());
        self
    }

    /// Returns the text's `image` answer.
    fn image(&self) -> Value {
        let mut runs: Vec<(&str, u64, u64)> = Vec::new();
        for (origin, ordinal, _) in &self.0 {
            match runs.last_mut() {
                Some((of, first, width)) if of == origin && *first + *width == *ordinal => *width += 1,
                _ => runs.push((origin, *ordinal, 1)),
            }
        }
        let runs: Vec<Value> = runs.into_iter().map(|(origin, first, width)| json!({"i_start": format!("{origin}.0.1.{first}"), "width": width.to_string()})).collect();
        json!({"resp": "runs", "as_of": AT, "runs": runs})
    }

    /// Returns the text's bytes from the position `from`, `width` of them.
    fn bytes(&self, from: u64, width: u64) -> String {
        String::from_utf8(self.0.iter().skip(from as usize - 1).take(width as usize).map(|cell| cell.2).collect()).expect("text")
    }
}

/// A board answering from modelled texts, every frame kept.
struct Board {
    /// The document the draft is compared with.
    since: Doc,
    /// The draft as each image of it finds it; the last stands.
    drafts: Vec<Doc>,
    /// Which of the drafts the next read finds.
    now: Cell<usize>,
    /// The documents a read by identity may not read.
    withheld: Vec<&'static str>,
    /// A document every read by identity is refused over, whatever it asks.
    refusing: Option<&'static str>,
    /// The addresses the board holds no value at.
    unminted: Vec<(&'static str, u64)>,
    /// The frames sent, in order.
    sent: RefCell<Vec<Value>>,
}

impl Board {
    /// Returns a board holding `since` and a draft that stands as `draft`.
    fn of(since: &Doc, draft: &Doc) -> Board {
        Board { since: since.clone(), drafts: vec![draft.clone()], now: Cell::new(0), withheld: Vec::new(), refusing: None, unminted: Vec::new(), sent: RefCell::new(Vec::new()) }
    }

    /// Returns the ops of the frames sent, in order.
    fn ops(&self) -> Vec<String> {
        self.sent.borrow().iter().map(|frame| frame["op"].as_str().unwrap_or_default().to_string()).collect()
    }

    /// Returns the diff's outcome for `args` beside `doc` and `since`, the
    /// two images planned as read.
    fn diff(&self, mut args: Value) -> Result<Answer, Refusal> {
        args["doc"] = Value::from(DOC);
        args["since"] = Value::from(SINCE);
        Asked::read(&args).and_then(|asked| diff(self, &asked, &as_read))
    }

    /// Returns the diff's answer for `args`, an answer that is data.
    fn diffed(&self, args: Value) -> Value {
        let answer = self.diff(args).unwrap_or_else(|refusal| panic!("an answer: {refusal}"));
        assert!(!answer.is_error, "{}", answer.value);
        answer.into_value()
    }
}

/// The mapping of a diff no correspondence record touches: the two images
/// as read.
fn as_read(before: &Image, now: &Image) -> Result<(Image, Image), Refusal> {
    Ok((before.clone(), now.clone()))
}

/// Returns the board's refusal of a read by identity over `document`.
///
/// It is the wire's own form: the code, and the document under `site.addr`.
fn withheld(document: &str) -> Refusal {
    Refusal::Board(Refused {
        status: 200,
        code: "withheld".into(),
        detail: None,
        op: Some("retrieve_i".into()),
        body: json!({"resp": "rejected", "op": "retrieve_i", "code": "withheld", "disposition": "reorder", "site": {"addr": document}}),
    })
}

/// Returns a natural spelled as the last component of a width or a start.
fn last(text: &Value) -> u64 {
    text.as_str().and_then(|text| text.rsplit('.').next()).and_then(|last| last.parse().ok()).expect("a natural")
}

impl Calls for Board {
    fn op(&self, frame: Value) -> Result<Value, Refusal> {
        self.sent.borrow_mut().push(frame.clone());
        let draft = &self.drafts[self.now.get()];
        match frame["op"].as_str() {
            Some("image") if frame["d"] == SINCE => Ok(self.since.image()),
            Some("image") => {
                assert_eq!(frame, frames::image(DOC, 1, u64::MAX), "the draft's whole content");
                let image = draft.image();
                self.now.set((self.now.get() + 1).min(self.drafts.len() - 1));
                Ok(image)
            }
            Some("retrieve_doc_v_span_set") => {
                let set = if draft.0.is_empty() { json!([]) } else { json!([{"start": "1.1", "width": format!("0.{}", draft.0.len())}]) };
                Ok(json!({"resp": "span_set", "as_of": AT, "set": set}))
            }
            Some("retrieve_v") => {
                let spec = &frame["specs"][0];
                assert_eq!(spec["doc"], DOC, "the text of `since` is never read by position");
                Ok(json!({"resp": "delivery", "as_of": AT, "items": [{"content": draft.bytes(last(&spec["span"]["start"]), last(&spec["span"]["width"]))}]}))
            }
            Some("retrieve_i") => {
                if let Some(document) = self.refusing {
                    assert!(self.ops().iter().filter(|op| *op == "retrieve_i").count() <= 2, "a read refused over one document twice is made no third time");
                    return Err(withheld(document));
                }
                let held: HashMap<(&str, u64), u8> = self.since.0.iter().map(|(origin, ordinal, byte)| ((*origin, *ordinal), *byte)).collect();
                let mut items = Vec::new();
                for span in frame["spans"].as_array().expect("spans") {
                    let start = span["start"].as_str().expect("a start");
                    let (origin, first) =
                        start.rsplit_once('.').map(|(prefix, first)| (prefix.strip_suffix(".0.1").expect("a content address"), first.parse::<u64>().expect("an ordinal"))).expect("an address");
                    if let Some(document) = self.withheld.iter().find(|document| **document == origin) {
                        return Err(withheld(document));
                    }
                    for ordinal in first..first + last(&span["width"]) {
                        let value = match held.get(&(origin, ordinal)).filter(|_| !self.unminted.contains(&(origin, ordinal))) {
                            Some(byte) => json!({"content": char::from(*byte).to_string()}),
                            None => Value::Null,
                        };
                        items.push(json!({"at": format!("{origin}.0.1.{ordinal}"), "value": value}));
                    }
                }
                Ok(json!({"resp": "i_delivery", "as_of": AT, "items": items}))
            }
            other => panic!("a diff sends no {other:?}: {frame}"),
        }
    }

    fn held(&self) -> Result<Value, Refusal> {
        panic!("a diff holds no line")
    }

    fn drop_held(&self, held: u64) -> Result<Value, Refusal> {
        panic!("a diff drops no line: {held}")
    }
}

/// Eight lines, no two equal as text.
const EIGHT: &str = "alpha one\nbravo two\ncharlie three\ndelta four\necho five\nfoxtrot six\ngolf seven\nhotel eight\n";

/// Returns `rows` as the answer carries them.
fn said(rows: &[&str]) -> Value {
    json!(rows)
}

/// A diff reads images, the draft's text and the gone spans by identity.
///
/// `since` is imaged; the draft is imaged, its extent and its text read,
/// and imaged again; and the one line the draft no longer holds is read by
/// identity, at the addresses `since`'s image gives it. No text of `since`
/// is read by position, and `compare` is not called. The answer counts the
/// change by identity in decimal strings and draws the one hunk the two
/// changes' context makes, touching (the mutants
/// that read the gone line at the draft's positions, drop the second image,
/// or read `since` whole send other frames, or draw another line).
#[test]
fn a_diff_reads_two_images_the_drafts_text_between_two_more_and_the_gone_spans_by_identity() {
    // Typed from an ordinal of its own, so an address is no position.
    let since = Doc::typed(SINCE, 1000, EIGHT);
    let draft = since.pick(&[1, 2, 3, 5, 6, 7, 8]).then(&Doc::typed(DOC, 1, "india nine\n"));
    let board = Board::of(&since, &draft);
    let answer = board.diffed(json!({}));
    assert_eq!(board.ops(), ["image", "image", "retrieve_doc_v_span_set", "retrieve_v", "image", "retrieve_i"]);
    let sent = board.sent.borrow();
    assert_eq!(sent[0], frames::image(SINCE, 1, u64::MAX), "the whole content of `since`");
    let delta = ("alpha one\nbravo two\ncharlie three\n".len()) as u64 + 1000;
    assert_eq!(sent[5], frames::retrieve_i(&[(&format!("{SINCE}.0.1.{delta}"), 11)]), "the gone line, by its own addresses");
    crate::shapes::assert_declared("TextDiffed", &answer);
    let shared = EIGHT.len() - 11;
    assert_eq!(
        answer,
        json!({
            "outcome": "diffed", "doc": DOC, "since": SINCE, "as_of": AT, "shared": shared.to_string(), "bytes": {"new": "11", "gone": "11", "moved": "0"},
            "lines": {"added": "1", "removed": "1", "moved": "0"},
            "rows": ["@@ -2,7 +2,7 @@", " 2\tbravo two", " 3\tcharlie three", "-4\tdelta four", " 4\techo five", " 5\tfoxtrot six", " 6\tgolf seven", " 7\thotel eight", "+8\tindia nine"],
        })
    );
}

/// An edit and a move are told in one diff, the move with its note.
///
/// A line changed is a line gone and a line new; a block moved is drawn
/// where it stands, `>`, with one `<` row where it left, no line of it gone
/// or new; and the note names its lines before and now.
#[test]
fn an_edit_and_a_move_are_told_in_one_diff_the_move_with_its_note() {
    let since = Doc::typed(SINCE, 1, EIGHT);
    let draft = since.pick(&[1, 6, 7]).then(&Doc::typed(DOC, 1, "bravo 2\n")).then(&since.pick(&[3, 4, 5, 8]));
    let answer = Board::of(&since, &draft).diffed(json!({}));
    assert_eq!(
        answer["rows"],
        said(&[
            "@@ -1,8 +1,8 @@",
            " 1\talpha one",
            "-2\tbravo two",
            ">2\tfoxtrot six",
            ">3\tgolf seven",
            "+4\tbravo 2",
            " 5\tcharlie three",
            " 6\tdelta four",
            " 7\techo five",
            "<\t(lines 6–7 moved to 2–3)",
            " 8\thotel eight"
        ])
    );
    assert_eq!(answer["notes"], json!([{"kind": "moved", "before": [6, 7], "now": [2, 3]}]));
    assert_eq!((&answer["lines"], &answer["bytes"]), (&json!({"added": "1", "removed": "1", "moved": "2"}), &json!({"new": "8", "gone": "10", "moved": "23"})));
    // A block typed again reads the same and is said re-typed, never moved.
    let retyped = since.pick(&[1]).then(&Doc::typed(DOC, 1, "bravo two\ncharlie three\n")).then(&since.pick(&[4, 5, 6, 7, 8]));
    let answer = Board::of(&since, &retyped).diffed(json!({}));
    assert_eq!((&answer["rows"], &answer["notes"]), (&json!([]), &json!([{"kind": "retyped", "before": [2, 3], "now": [2, 3]}])), "unchanged as text: no row, and the note says the bytes are new");
    crate::shapes::assert_declared("TextDiffed", &answer);
    crate::shapes::assert_declared("TextDiffNote", &answer["notes"][0]);
}

/// `stat` reads no text, and answers the counts alone.
#[test]
fn stat_reads_no_text_and_answers_the_counts_alone() {
    let since = Doc::typed(SINCE, 1, EIGHT);
    let draft = since.pick(&[1, 6, 7, 2, 3, 5, 8]);
    let board = Board::of(&since, &draft);
    let answer = board.diffed(json!({"stat": true}));
    assert_eq!(board.ops(), ["image", "image"], "one image of each document, and nothing else");
    let moved = "foxtrot six\ngolf seven\n".len();
    crate::shapes::assert_declared("TextDiffed", &answer);
    assert_eq!(answer, json!({"outcome": "diffed", "doc": DOC, "since": SINCE, "as_of": AT, "shared": draft.0.len().to_string(), "bytes": {"new": "0", "gone": "11", "moved": moved.to_string()}}));
    let same = Board::of(&since, &since);
    assert_eq!(same.diffed(json!({"stat": true})), json!({"outcome": "unchanged", "doc": DOC, "since": SINCE, "as_of": AT}));
    assert_eq!(same.ops(), ["image", "image"]);
}

/// Nothing changed is `unchanged`, and texts apart read nothing of `since`.
///
/// A draft that holds every position of `since` where `since` holds it is
/// unchanged. A draft that shares no position with it answers `shared`
/// `"0"` and the counts, no rows drawn and no read by identity made; and
/// against an empty `since` every line of the draft is new, drawn, no read
/// by identity being owed.
#[test]
fn nothing_changed_is_unchanged_and_texts_that_share_nothing_read_nothing_of_since() {
    let since = Doc::typed(SINCE, 1, EIGHT);
    let board = Board::of(&since, &since);
    let answer = board.diffed(json!({}));
    crate::shapes::assert_declared("TextDiffUnchanged", &answer);
    assert_eq!(answer, json!({"outcome": "unchanged", "doc": DOC, "since": SINCE, "as_of": AT}));
    let apart = Board::of(&since, &Doc::typed(DOC, 1, "other words\n"));
    let answer = apart.diffed(json!({}));
    assert_eq!(answer, json!({"outcome": "diffed", "doc": DOC, "since": SINCE, "as_of": AT, "shared": "0", "bytes": {"new": "12", "gone": EIGHT.len().to_string(), "moved": "0"}}));
    assert!(!apart.ops().contains(&"retrieve_i".to_string()), "nothing of `since` is read");
    let empty = Board::of(&Doc::default(), &Doc::typed(DOC, 1, "one\ntwo\n"));
    let answer = empty.diffed(json!({}));
    assert_eq!((&answer["shared"], &answer["rows"]), (&json!("0"), &said(&["@@ -0,0 +1,2 @@", "+1\tone", "+2\ttwo"])), "a mark of an empty draft: every line is new");
    assert!(!empty.ops().contains(&"retrieve_i".to_string()));
    let emptied = Board::of(&Doc::typed(SINCE, 1, "one\ntwo\n"), &Doc::default());
    assert_eq!(emptied.diffed(json!({}))["rows"], said(&["@@ -1,2 +0,0 @@", "-1\tone", "-2\ttwo"]));
}

/// A draft changed between its two images is read again.
///
/// One that keeps changing is refused.
/// The first image finds one text and the read another: the three reads are
/// made again, and the diff is of the draft as they then find it — where
/// the draft lost lines between the two, and where two lines changed places
/// and it holds as many positions as before, which the two images alone
/// tell apart. A draft that changes before every image is refused
/// `arrangement_moved` after three rounds, with nothing of `since` read (the
/// mutant that drops the second image draws the first image's pairs over
/// the second text).
#[test]
fn a_draft_changed_between_its_two_images_is_read_again_and_one_that_keeps_changing_is_refused() {
    let since = Doc::typed(SINCE, 1, EIGHT);
    let (first, second) = (since.pick(&[1, 2, 3, 4, 5, 6, 7]), since.pick(&[1, 2, 3, 4]));
    let mut board = Board::of(&since, &first);
    board.drafts.push(second);
    let answer = board.diffed(json!({}));
    assert_eq!(board.ops(), ["image", "image", "retrieve_doc_v_span_set", "retrieve_v", "image", "image", "retrieve_doc_v_span_set", "retrieve_v", "image", "retrieve_i"]);
    assert_eq!(
        answer["rows"],
        said(&["@@ -3,6 +3,2 @@", " 3\tcharlie three", " 4\tdelta four", "-5\techo five", "-6\tfoxtrot six", "-7\tgolf seven", "-8\thotel eight"]),
        "the draft as the second round found it"
    );
    // Two lines change places between the image and the read: as many
    // positions, another arrangement.
    let swapped = since.pick(&[1, 2, 7, 4, 5, 6, 3, 8]);
    let mut board = Board::of(&since, &since);
    board.drafts.push(swapped.clone());
    let answer = board.diffed(json!({}));
    assert_eq!(board.ops().iter().filter(|op| *op == "image").count(), 1 + 2 * 2, "read again: the two images differ, though the text is as long");
    assert_eq!(answer, Board::of(&since, &swapped).diffed(json!({})), "the draft as it stands, its own image over its own text");
    assert_eq!(answer["notes"], json!([{"kind": "moved", "before": [7, 7], "now": [3, 3]}, {"kind": "moved", "before": [3, 3], "now": [7, 7]}]), "{answer}");
    let mut moving = Board::of(&since, &first);
    moving.drafts = (1..=7).map(|lines| since.pick(&(1..=lines).collect::<Vec<_>>())).collect();
    let answer = moving.diff(json!({})).expect("an answer");
    crate::shapes::assert_declared("TextRefused", &answer.value);
    assert_eq!(answer, Answer { value: json!({"outcome": "refused", "cause": "arrangement_moved", "doc": DOC, "reads": 3}), is_error: false });
    assert_eq!(moving.ops().len(), 1 + 3 * 4, "three rounds, and no read by identity");
    assert_eq!(DIFF_TRIES, 3);
}

/// A gone span of an origin the session may not read is told withheld.
///
/// The read by identity refuses whole where one span lies in a document the
/// session may not read: its spans are told as a withheld value each, and
/// the read is made again without them, so the lines of every other origin
/// are drawn; `masked` says the numbers past the withheld value are the
/// reader's own. A refusal naming a document a second time, or one none of
/// the gone spans lies in, is the call's: the read is made again once for
/// an origin and no more (the mutants that fail the diff on the first
/// refusal, make the read again whatever the refusal names, or take a
/// document no span lies in for an origin, answer no rows, read a third
/// time, or read twice).
#[test]
fn a_gone_span_of_an_origin_the_session_may_not_read_is_told_withheld() {
    let since = Doc::typed(SINCE, 1, "one\ntwo\n").then(&Doc::typed(OTHER, 1, "quoted\nwords\n")).then(&Doc::typed(SINCE, 100, "three\nfour\n"));
    let draft = since.pick(&[1, 6]);
    let mut board = Board::of(&since, &draft);
    board.withheld = vec![OTHER];
    let answer = board.diffed(json!({}));
    assert_eq!(board.ops()[5..], ["retrieve_i", "retrieve_i"], "refused once, and made again without the origin's spans");
    let sent = board.sent.borrow();
    assert_eq!(sent[6], frames::retrieve_i(&[(&format!("{SINCE}.0.1.5"), 4), (&format!("{SINCE}.0.1.100"), 6)]), "the spans of the origin the session reads");
    assert_eq!(answer["rows"], said(&["@@ -1,4 +1,2 @@", " 1\tone", "-2\ttwo", "-3\t{…}three", " 2\tfour"]), "the withheld value holds no line break");
    assert_eq!((&answer["masked"], &answer["bytes"]), (&json!(true), &json!({"new": "0", "gone": "23", "moved": "0"})));
    drop(sent);
    let mut twice = Board::of(&Doc::typed(OTHER, 1, "quoted\n"), &Doc::default());
    twice.withheld = vec![OTHER, OTHER];
    let answer = twice.diffed(json!({}));
    assert_eq!(
        (twice.ops().iter().filter(|op| *op == "retrieve_i").count(), &answer["rows"]),
        (1, &said(&["@@ -1,1 +0,0 @@", "-1\t{…}", "\\ no line break at the end"])),
        "every gone span withheld: no second read"
    );
    // A board that names the origin again, none of its spans asked.
    let reads = |board: &Board| board.ops().iter().filter(|op| *op == "retrieve_i").count();
    let mut again = Board::of(&since, &draft);
    again.refusing = Some(OTHER);
    let refused = again.diff(json!({})).unwrap_err();
    assert_eq!((refused.name(), reads(&again)), ("withheld", 2), "named a second time: the call's refusal, the read made again once");
    assert_eq!(again.sent.borrow().last(), Some(&frames::retrieve_i(&[(&format!("{SINCE}.0.1.5"), 4), (&format!("{SINCE}.0.1.100"), 6)])), "the second read asked nothing of the origin");
    // A refusal naming a document none of the gone spans lies in.
    let mut stranger = Board::of(&since, &draft);
    stranger.refusing = Some("1.0.1.0.99");
    let refused = stranger.diff(json!({})).unwrap_err();
    assert_eq!((refused.name(), reads(&stranger)), ("withheld", 1), "no span of its content: the call's refusal at once");
}

/// A position the board holds no value at is `unread`, never text.
#[test]
fn a_position_the_board_holds_no_value_at_is_unread_never_text() {
    let since = Doc::typed(SINCE, 1, EIGHT);
    let mut board = Board::of(&since, &since.pick(&[1, 2, 3]));
    board.unminted = vec![(SINCE, 40)];
    let answer = board.diff(json!({})).expect("an answer");
    assert_eq!(answer, Answer { value: json!({"outcome": "refused", "cause": "unread", "doc": DOC, "op": "retrieve_i"}), is_error: true });
}

/// The gone spans are read in parts no larger than their bounds.
///
/// A part asks no more positions than the delivery budget, no more spans
/// than a wire list, and no more positions than the dialer's answer cap
/// holds at the room one takes under its span's addresses; a span past a
/// part goes on in the next, from where the last left it; and a span marked
/// withheld, or read to its end, is in none (the mutant that sizes a part by
/// the delivery budget alone asks an answer past the cap under a long
/// address).
#[test]
fn the_gone_spans_are_read_in_parts_no_larger_than_their_bounds() {
    let span = |prefix: &str, width: u64| Gone { before: 1, prefix: prefix.to_string(), first: 1, width };
    let short = "1.0.1.0.65.0.1";
    // The room a position takes under a span's longest address, its last.
    let room = |gone: &Gone| (frames::I_ITEM_ROOM + format!("{}.{}", gone.prefix, gone.first + gone.width).len()) as u64;
    let budget = (MAX_ANSWER_BYTES - 64) as u64;
    // One long span under a short address: the delivery budget bounds a part.
    let long = [span(short, 3 * READ_POSITIONS + 5)];
    let asked = parts(&long, &[0], &[false]);
    assert!(READ_POSITIONS * room(&long[0]) <= budget, "premise: the budget's positions fit the cap at this room");
    assert_eq!(
        asked.iter().map(|part| (part.len(), part[0].into, part[0].width)).collect::<Vec<_>>(),
        [(1, 0, READ_POSITIONS), (1, READ_POSITIONS, READ_POSITIONS), (1, 2 * READ_POSITIONS, READ_POSITIONS), (1, 3 * READ_POSITIONS, 5)]
    );
    assert_eq!(parts(&long, &[READ_POSITIONS + 7], &[false])[0][0], Asking { span: 0, into: READ_POSITIONS + 7, width: READ_POSITIONS }, "from where the last read left it");
    // Under a long address the answer cap bounds a part first.
    let deep = format!("1.0.1{}.0.1", ".1".repeat(60));
    let fits = budget / room(&span(&deep, READ_POSITIONS));
    assert!(fits < READ_POSITIONS, "premise: at this room the cap holds fewer positions than the budget");
    let asked = parts(&[span(&deep, READ_POSITIONS)], &[0], &[false]);
    assert_eq!(asked.iter().map(|part| (part[0].into, part[0].width)).collect::<Vec<_>>(), [(0, fits), (fits, fits), (2 * fits, READ_POSITIONS - 2 * fits)], "each part within the cap");
    // Many short spans: a wire list's spans bound a part, and every bound holds.
    let many: Vec<Gone> = (0..2 * MAX_WIRE_LIST as u64 + 3).map(|k| Gone { before: k + 1, prefix: short.to_string(), first: 2 * k + 1, width: 1 }).collect();
    let asked = parts(&many, &vec![0; many.len()], &vec![false; many.len()]);
    assert_eq!(asked.iter().map(Vec::len).collect::<Vec<_>>(), [MAX_WIRE_LIST, MAX_WIRE_LIST, 3]);
    let mixed = [span(short, 100_000), span(&deep, 50_000), span(short, 90_000)];
    for part in parts(&mixed, &[0, 0, 0], &[false, false, false]) {
        let positions: u64 = part.iter().map(|asking| asking.width).sum();
        let bytes: u64 = part.iter().map(|asking| asking.width * room(&mixed[asking.span])).sum();
        assert!(positions <= READ_POSITIONS && bytes <= budget && part.len() <= MAX_WIRE_LIST, "{part:?}");
    }
    assert_eq!(parts(&mixed, &[100_000, 0, 90_000], &[false, true, false]), Vec::<Vec<Asking>>::new(), "read to its end, or withheld: in no part");
}

/// A gone stretch wider than one part is read in two, and drawn whole.
#[test]
fn a_gone_stretch_wider_than_one_part_is_read_in_two_and_drawn_whole() {
    let lines = (READ_POSITIONS as usize + 10) / 2;
    let since = Doc::typed(SINCE, 1, &"x\n".repeat(lines)).then(&Doc::typed(SINCE, 900_000, "the last line\n"));
    let draft = since.pick(&[lines + 1]);
    let board = Board::of(&since, &draft);
    let answer = board.diffed(json!({}));
    assert_eq!(board.ops()[5..], ["retrieve_i", "retrieve_i"]);
    assert_eq!(last(&board.sent.borrow()[6]["spans"][0]["start"]), READ_POSITIONS + 1, "the second part goes on where the first ended");
    let rows = answer["rows"].as_array().expect("rows");
    assert_eq!(
        (rows[0].as_str(), rows[1].as_str(), rows[7].as_str()),
        (Some(format!("@@ -1,{} +1,1 @@", lines + 1).as_str()), Some("-1\tx"), Some(format!("-…\t({} more lines)", lines - 9).as_str()))
    );
    assert_eq!((answer["bytes"]["gone"].as_str(), answer["lines"]["removed"].as_str()), (Some((2 * lines).to_string().as_str()), Some(lines.to_string().as_str())));
}

/// The texts a diff tells whole, and its pairs, are held to their bounds.
///
/// `since` past the cap is refused `too_large` naming it before any text is
/// read; with `stat` it is counted, no text being told. Two images that
/// make more pairs than a plan is made over are refused naming the pairs.
#[test]
fn the_texts_a_diff_tells_whole_are_held_to_the_cap_and_its_pairs_to_the_plans_bound() {
    let wide = Doc(vec![(SINCE, 1, b'x')]);
    let mut board = Board::of(&wide, &Doc::typed(DOC, 1, "one\n"));
    // An image of one run wider than the cap, spelled as the board would.
    struct Wide<'b>(&'b Board);
    impl Calls for Wide<'_> {
        fn op(&self, frame: Value) -> Result<Value, Refusal> {
            if frame["op"] == "image" && frame["d"] == SINCE {
                self.0.sent.borrow_mut().push(frame);
                return Ok(json!({"resp": "runs", "as_of": AT, "runs": [{"i_start": format!("{SINCE}.0.1.1"), "width": (MAX_DRAFT_POSITIONS + 1).to_string()}]}));
            }
            self.0.op(frame)
        }
        fn held(&self) -> Result<Value, Refusal> {
            self.0.held()
        }
        fn drop_held(&self, held: u64) -> Result<Value, Refusal> {
            self.0.drop_held(held)
        }
    }
    let asked = |args: &Value| Asked::read(args).and_then(|asked| diff(&Wide(&board), &asked, &as_read));
    let answer = asked(&json!({"doc": DOC, "since": SINCE})).expect("an answer");
    assert_eq!(
        answer,
        Answer {
            value: json!({"outcome": "refused", "cause": "too_large", "doc": DOC, "what": "since", "positions": (MAX_DRAFT_POSITIONS + 1).to_string(), "cap": MAX_DRAFT_POSITIONS.to_string()}),
            is_error: false
        }
    );
    assert_eq!(board.ops(), ["image"], "refused before any text is read");
    let counted = asked(&json!({"doc": DOC, "since": SINCE, "stat": true})).expect("an answer").into_value();
    assert_eq!((counted["outcome"].as_str(), counted["bytes"]["gone"].as_str()), (Some("diffed"), Some((MAX_DRAFT_POSITIONS + 1).to_string().as_str())), "the counts alone tell no text");
    // One line placed three hundred times in each text: ninety thousand pairs.
    let line = Doc::typed(SINCE, 1, "again\n");
    let placed = Doc((0..300).flat_map(|_| line.0.iter().copied()).collect());
    board = Board::of(&placed, &placed);
    let answer = board.diff(json!({"stat": true})).expect("an answer");
    crate::shapes::assert_declared("TextRefused", &answer.value);
    assert_eq!(answer.value, json!({"outcome": "refused", "cause": "too_large", "doc": DOC, "what": "pairs", "pairs": "90000", "cap": "65536"}));
}

/// A later hunk starts the rows, and a hunk past the last is refused.
#[test]
fn a_later_hunk_starts_the_rows_and_a_hunk_past_the_last_is_refused() {
    let text: String = (1..=12).map(|n| format!("line number {n}\n")).collect();
    let since = Doc::typed(SINCE, 1, &text);
    let board = Board::of(&since, &since.pick(&[1, 2, 4, 5, 6, 7, 8, 10, 11, 12]));
    let whole = board.diffed(json!({}));
    assert_eq!(
        (whole["rows"].as_array().map(Vec::len), whole["rows"][0].as_str(), whole["rows"][6].as_str(), whole.get("next_hunk")),
        (Some(12), Some("@@ -1,5 +1,4 @@"), Some("@@ -7,5 +6,4 @@"), None)
    );
    let second = board.diffed(json!({"hunk": 2}));
    assert_eq!((second["rows"].as_array().map(Vec::len), second["rows"][0].as_str()), (Some(6), Some("@@ -7,5 +6,4 @@")));
    assert_eq!(second["lines"], whole["lines"], "the counts are the whole diff's");
    let past = board.diff(json!({"hunk": 3})).expect("an answer");
    crate::shapes::assert_declared("TextRefused", &past.value);
    assert_eq!(past, Answer { value: json!({"outcome": "refused", "cause": "no_such_hunk", "doc": DOC, "hunk": 3, "count": 2}), is_error: false });
}

/// The members are read each in its form.
///
/// A read's refusal is the call's.
#[test]
fn the_members_are_read_each_in_its_form_and_a_reads_refusal_is_the_calls() {
    let in_form = json!({"doc": DOC, "since": SINCE, "stat": true, "hunk": 2});
    assert_eq!(Asked::read(&in_form), Ok(Asked { doc: DOC, since: SINCE, stat: true, hunk: 2 }));
    assert_eq!(Asked::read(&json!({"doc": DOC, "since": SINCE, "stat": null, "hunk": null})), Ok(Asked { doc: DOC, since: SINCE, stat: false, hunk: 1 }), "absent, or null: the defaults");
    for (member, value) in [
        ("doc", json!("1..2")),
        ("since", json!(7)),
        ("since", json!("01.1")),
        ("stat", json!("yes")),
        ("stat", json!(1)),
        ("hunk", json!(0)),
        ("hunk", json!("2")),
        ("hunk", json!(1.5)),
        ("hunk", json!(-1)),
    ] {
        let mut args = in_form.clone();
        args[member] = value;
        assert_eq!(Asked::read(&args).unwrap_err().to_value()["what"], member, "{args}");
    }
    assert_eq!(Asked::read(&json!({"doc": DOC})).unwrap_err().to_value()["what"], "since");
    assert_eq!(Asked::read(&json!({"doc": 7, "since": 7})).unwrap_err().to_value()["what"], "doc", "the first member not of its form");
    // The board's refusal of the first read is the call's, nothing else asked.
    struct Refusing(RefCell<Vec<Value>>);
    impl Calls for Refusing {
        fn op(&self, frame: Value) -> Result<Value, Refusal> {
            self.0.borrow_mut().push(frame);
            Err(Refusal::Board(Refused {
                status: 200,
                code: "withheld".into(),
                detail: None,
                op: Some("image".into()),
                body: json!({"resp": "rejected", "code": "withheld", "site": {"addr": SINCE}}),
            }))
        }
        fn held(&self) -> Result<Value, Refusal> {
            panic!("no line")
        }
        fn drop_held(&self, _: u64) -> Result<Value, Refusal> {
            panic!("no line")
        }
    }
    let refusing = Refusing(RefCell::new(Vec::new()));
    let refused = Asked::read(&in_form).and_then(|asked| diff(&refusing, &asked, &as_read)).unwrap_err();
    assert_eq!((refused.name(), refusing.0.borrow().len()), ("withheld", 1));
}

/// The two images are mapped once, after the draft's last image.
///
/// The mapping is handed `since`'s image and the draft's last — after the
/// draft's text was read and it was imaged again, a round made again where
/// the draft moved, or after the two images alone under `stat` — and the
/// plan is made over what it answers: a mapping that sends both images to
/// one stand-in identity answers `unchanged`, nothing read by identity; a
/// mapping's refusal is the call's, nothing read past it (the mutants that
/// map before the draft is read, map `since` alone, or plan the images as
/// read answer otherwise).
#[test]
fn the_two_images_are_mapped_once_after_the_drafts_last_image_and_planned_as_mapped() {
    let since = Doc::typed(SINCE, 1, EIGHT);
    let (first, last) = (since.pick(&[1, 2, 3]), Doc::typed(DOC, 1, EIGHT));
    let mut board = Board::of(&since, &first);
    board.drafts.push(last.clone());
    let seen: RefCell<Vec<(Vec<String>, Image, Image)>> = RefCell::new(Vec::new());
    let stand_in = |before: &Image, now: &Image| -> Result<(Image, Image), Refusal> {
        seen.borrow_mut().push((board.ops(), before.clone(), now.clone()));
        Ok((now.clone(), now.clone()))
    };
    let asked = |args: Value| Asked::read(&args).and_then(|asked| diff(&board, &asked, &stand_in));
    let answer = asked(json!({"doc": DOC, "since": SINCE})).expect("an answer");
    assert_eq!(answer, Answer::data(json!({"outcome": "unchanged", "doc": DOC, "since": SINCE, "as_of": AT})), "planned as mapped");
    let read = ["image", "image", "retrieve_doc_v_span_set", "retrieve_v", "image", "image", "retrieve_doc_v_span_set", "retrieve_v", "image"];
    let image = |doc: &Doc| whole_image(&doc.image()).expect("an image");
    assert_eq!(*seen.borrow(), [(read.map(String::from).to_vec(), image(&since), image(&last))], "once, after the draft's last image, the draft as it then stood");
    assert_eq!(board.ops(), read, "nothing read past the mapping");
    // The counts alone: mapped after the two images.
    let board = Board::of(&since, &last);
    seen.borrow_mut().clear();
    let stand_in = |before: &Image, now: &Image| -> Result<(Image, Image), Refusal> {
        seen.borrow_mut().push((board.ops(), before.clone(), now.clone()));
        Ok((now.clone(), now.clone()))
    };
    let counted = Asked::read(&json!({"doc": DOC, "since": SINCE, "stat": true})).and_then(|asked| diff(&board, &asked, &stand_in)).expect("an answer");
    assert_eq!(counted.value["outcome"], "unchanged");
    assert_eq!(seen.borrow().iter().map(|(ops, ..)| ops.clone()).collect::<Vec<_>>(), [["image", "image"].map(String::from).to_vec()]);
    // A mapping's refusal is the call's.
    let board = Board::of(&since, &last);
    let refusing = |_: &Image, _: &Image| -> Result<(Image, Image), Refusal> { Err(Refusal::shell(crate::refusal::Name::UNREADABLE, json!({"doc": "1.0.1.0.7"}))) };
    let refused = Asked::read(&json!({"doc": DOC, "since": SINCE})).and_then(|asked| diff(&board, &asked, &refusing)).unwrap_err();
    assert_eq!((refused.name(), board.ops().len()), ("unreadable", 5), "nothing read by identity");
}
