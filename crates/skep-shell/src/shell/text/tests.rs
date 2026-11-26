//! The text edit's unit suite: the find, the trim, the text a delivery is
//! read into, spliced and rearranged, the edit against a scripted board
//! (`Script`, the edit's [`Calls`]) — its one frame, the board's verdict
//! on it, a lost answer asked again and settled from the change feed — and
//! the edit through the shell's rows scripted (`Rowed`, its [`Rows`]): a
//! death followed to its re-open, the error member, the halts left for the
//! row to say. The scripted boards serve the child suites of `text.edit`,
//! `text.move` and `text.mark` too (`edit/tests.rs`, `moving/tests.rs`,
//! `mark/tests.rs`). The rows themselves, their order and their door, run
//! against the daemon in `shell/tests/text.rs`.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::time::Instant;

use skep_client::dial::DialError;
use skep_client::halt::Refused;

use super::*;

/// The draft every scripted edit names.
pub(super) const DOC: &str = "1.0.1.0.64";

/// The text the scripted drafts hold: each word an edit names stands once.
pub(super) const CODE: &str = "fn main() {\n    let total = add(left, right);\n    println!(\"{total}\");\n}\n";

/// Returns the content ordinal at which `word` begins in `text`.
pub(super) fn ordinal_of(text: &str, word: &str) -> u64 {
    text.find(word).unwrap_or_else(|| panic!("`{word}` stands in the text")) as u64 + 1
}

/// Returns the text a delivery's `items` hold.
pub(super) fn text_of(items: Value) -> Text {
    let mut text = Text::default();
    for item in items.as_array().expect("items") {
        text.push(item).expect("an item the text counts");
    }
    text
}

// ── the find ────────────────────────────────────────────────────────────

/// The old text is found once, or refused with how often it stands.
///
/// A word that stands once is found at its byte's ordinal; one that stands
/// nowhere is nowhere; one that stands twice is counted twice, and
/// overlapping places are each counted, so a text that could be taken two
/// ways is never taken the first way (the mutant that takes the first match
/// answers the first `total`'s ordinal).
#[test]
fn the_old_text_is_found_once_or_refused_with_how_often_it_stands() {
    let text = text_of(json!([{"content": CODE}]));
    assert_eq!(text.positions(), CODE.len() as u64);
    assert_eq!(text.find(b"add"), Found::Once(ordinal_of(CODE, "add")));
    assert_eq!(text.find(b"fn"), Found::Once(1), "at the draft's first byte");
    assert_eq!(text.find(b"}\n"), Found::Once(CODE.len() as u64 - 1), "at its last");
    assert_eq!(text.find(CODE.as_bytes()), Found::Once(1), "the whole text");
    assert_eq!(text.find(b"subtract"), Found::Nowhere);
    assert_eq!(text.find(b"total"), Found::Many(2));
    assert_eq!(text.find(b"t"), Found::Many(CODE.matches('t').count() as u64));
    let repeated = text_of(json!([{"content": "aaa"}]));
    assert_eq!(repeated.find(b"aa"), Found::Many(2), "overlapping places are two places");
    assert_eq!(repeated.find(b"aaaa"), Found::Nowhere, "longer than the text");
    assert_eq!(Text::default().find(b"a"), Found::Nowhere, "an empty draft holds nothing");
}

/// Every place a text stands is found, whatever its bytes repeat.
///
/// The scan is held to the plain one — a window at each offset — over every
/// needle of up to four bytes of a two-letter alphabet in a seeded text of
/// it, where a prefix of the needle ends it over and over.
#[test]
fn every_place_a_text_stands_is_found_whatever_its_bytes_repeat() {
    let mut seed = 0x9E37_79B9_7F4A_7C15u64;
    let hay: Vec<u8> = (0..512)
        .map(|_| {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
            b'a' + ((seed >> 33) % 2) as u8
        })
        .collect();
    for len in 1..=4usize {
        for bits in 0..(1u32 << len) {
            let needle: Vec<u8> = (0..len).map(|k| b'a' + ((bits >> k) & 1) as u8).collect();
            let mut found = Vec::new();
            each_occurrence(&hay, &needle, |at| found.push(at));
            let plain: Vec<usize> = hay.windows(len).enumerate().filter(|(_, window)| *window == needle.as_slice()).map(|(at, _)| at).collect();
            assert_eq!(found, plain, "{:?}", String::from_utf8_lossy(&needle));
        }
    }
    let mut found = Vec::new();
    each_occurrence(b"abc", b"", |at| found.push(at));
    assert!(found.is_empty(), "an empty needle stands nowhere");
}

// ── the trim ────────────────────────────────────────────────────────────

/// The trim leaves standing what the two texts share at either end.
///
/// A whole line quoted around one changed word is reduced to that word's
/// changed bytes, at the word's own ordinal; an edit that only adds or only
/// takes out removes or inserts nothing; and the same text twice is no edit
/// (the mutant that trims nothing removes and inserts the whole line). The
/// trim's own counts are held where it lives, in `skep_client::text`'s
/// suite.
#[test]
fn the_trim_leaves_standing_what_the_two_texts_share_at_either_end() {
    let line = "    let total = add(left, right);\n";
    let at = ordinal_of(CODE, line);
    let changed = line.replace("add", "sub");
    assert_eq!(Edit::of(at, line, &changed), Edit { ordinal: ordinal_of(CODE, "add"), removed: 3, inserted: "sub" }, "a whole line quoted, three bytes changed");
    assert_eq!(Edit::of(at, line, &line.replace("add", "addition")), Edit { ordinal: ordinal_of(CODE, "add") + 3, removed: 0, inserted: "ition" }, "only added: the bytes after the word kept");
    assert_eq!(Edit::of(at, line, &line.replace("total = ", "")), Edit { ordinal: ordinal_of(CODE, "total"), removed: 8, inserted: "" }, "only taken out");
    assert_eq!(Edit::of(at, line, line), Edit { ordinal: at + line.len() as u64, removed: 0, inserted: "" }, "the same text is no edit");
    assert_eq!(Edit::of(1, "add", "sub"), Edit { ordinal: 1, removed: 3, inserted: "sub" }, "nothing shared");
    assert_eq!(Edit::of(1, "abcabc", "abc"), Edit { ordinal: 4, removed: 3, inserted: "" }, "the start is taken first, and the end from what is left");
    assert_eq!(Edit::of(1, "axa", "aa"), Edit { ordinal: 2, removed: 1, inserted: "" });
}

/// The trim never splits a character between kept bytes and new ones.
///
/// Two characters that share their first bytes, or their last, are replaced
/// whole: the shared start is cut back to a character boundary and the
/// shared end forward to one, in each text (the mutant that trims by bytes
/// keeps half of `é` and inserts half of `è`).
#[test]
fn the_trim_never_splits_a_character() {
    for (old, new, lead, tail) in [
        ("é", "è", 0, 0),     // C3 A9 / C3 A8: the first byte shared
        ("é", "ĩ", 0, 0),     // C3 A9 / C4 A9: the last byte shared
        ("a€b", "a₭b", 1, 1), // E2 82 AC / E2 82 AD: two bytes shared
        ("😀", "😁", 0, 0),   // F0 9F 98 80 / F0 9F 98 81: three shared
        ("x😀", "y😀", 0, 4), // a whole character shared at the end
        ("né", "nè", 1, 0),
        ("éa", "ĩa", 0, 1),
        ("日本語", "日本誤", 6, 0), // E8 AA 9E / E8 AA A4: the last differs in its third byte
    ] {
        assert_eq!(shared(old, new), (lead, tail), "{old:?} → {new:?}");
        let edit = Edit::of(1, old, new);
        assert_eq!(edit.inserted, &new[lead..new.len() - tail], "{old:?} → {new:?}: whole characters inserted");
        assert!(old.is_char_boundary(lead) && old.is_char_boundary(lead + edit.removed as usize), "{old:?} → {new:?}: whole characters removed");
    }
}

// ── the text ────────────────────────────────────────────────────────────

/// An atom takes one position, and no text matches across it.
///
/// A match beside an atom stands at the byte's own ordinal — the atom
/// counted as the one position it takes, whatever its bytes — and a text
/// that reads across it is refused, naming the atom's ordinal; a text that
/// stands once in a stretch is found though it would also read across (the
/// mutant that counts an atom's bytes, or forgets its position, answers
/// another ordinal).
#[test]
fn an_atom_takes_one_position_and_no_text_matches_across_it() {
    let text = text_of(json!([{"content": "alpha "}, {"atom": "one indivisible value"}, {"content": " beta gamma"}]));
    assert_eq!(text.positions(), 18, "six bytes, one atom, eleven bytes");
    assert_eq!(text.find(b"alpha"), Found::Once(1));
    assert_eq!(text.find(b" beta"), Found::Once(8), "directly after the atom");
    assert_eq!(text.find(b"beta"), Found::Once(9));
    assert_eq!(text.find(b"gamma"), Found::Once(14));
    assert_eq!(text.find(b"alpha  beta"), Found::Across { ordinal: 7, kind: "atom".into() });
    assert_eq!(text.find(b"one indivisible value"), Found::Nowhere, "an atom's bytes are no text");
    let leading = text_of(json!([{"atom_hex": "00ff"}, {"content": "abc"}]));
    assert_eq!((leading.positions(), leading.find(b"abc")), (4, Found::Once(2)));
    let twice = text_of(json!([{"content": "xa"}, {"atom": "v"}, {"content": "b ab"}]));
    assert_eq!(twice.find(b"ab"), Found::Once(6), "once in a stretch, and the place across the atom is no place");
    let two = text_of(json!([{"content": "a"}, {"atom": "v"}, {"atom": "w"}, {"content": "b"}]));
    assert_eq!((two.positions(), two.find(b"b")), (4, Found::Once(4)), "two atoms are two positions");
    assert_eq!(two.find(b"ab"), Found::Across { ordinal: 2, kind: "atom".into() });
}

/// Every value that is no text takes the positions it says, and is a gap.
///
/// A withheld run and a kind this adapter does not know each take their
/// `width`, and a link position one; a kind that carries no width it reads,
/// an item of two members and a text item whose value is no text are not
/// counted, and the edit is not made.
#[test]
fn every_value_that_is_no_text_takes_the_positions_it_says() {
    let text = text_of(
        json!([{"content": "ab"}, {"withheld": {"origin": "1.0.1.0.9", "width": "5"}}, {"content": "cd"}, {"future": {"width": 3, "more": true}}, {"ref": "1.0.1.0.64.0.2.1"}, {"content": "ef"}]),
    );
    assert_eq!(text.positions(), 15);
    assert_eq!((text.find(b"cd"), text.find(b"ef")), (Found::Once(8), Found::Once(14)));
    assert_eq!(text.find(b"bc"), Found::Across { ordinal: 3, kind: "withheld".into() });
    assert_eq!(text.find(b"de"), Found::Across { ordinal: 10, kind: "future".into() });
    for (item, kind) in [
        (json!({"future": {"origin": "1.0.1.0.9"}}), "future"),
        (json!({"future": "5"}), "future"),
        (json!({"withheld": {"origin": "1.0.1.0.9", "width": "0"}}), "withheld"),
        (json!({"content": 7}), "content"),
        (json!({"hex": "abc"}), "hex"),
        (json!({"hex": "zz"}), "hex"),
        (json!({"content": "a", "hex": "61"}), "item"),
        (json!("a"), "item"),
    ] {
        assert_eq!(Text::default().push(&item), Err(Uncounted { kind: kind.into() }), "{item}");
    }
}

/// A run a part boundary cut is one stretch, and hex is text.
///
/// A character cut between two parts turns each part's edge run to hex; the
/// two join into one stretch of the bytes the board holds, so the character
/// is found whole and a word that runs across the boundary at its own
/// ordinal. A run that is not UTF-8 at all is text by its bytes.
#[test]
fn a_run_a_part_boundary_cut_is_one_stretch_and_hex_is_text() {
    let mut text = text_of(json!([{"hex": "6162c3"}]));
    text.push(&json!({"hex": "a963"})).expect("the second part's edge run");
    text.push(&json!({"content": "d"})).expect("a later part");
    assert_eq!(text.positions(), 6);
    assert_eq!(text.find("é".as_bytes()), Found::Once(3));
    assert_eq!(text.find("abécd".as_bytes()), Found::Once(1), "one stretch across three parts");
    let raw = text_of(json!([{"hex": "ff00"}, {"atom": "v"}, {"hex": "c328"}]));
    assert_eq!((raw.find(&[0x00]), raw.find(&[0xc3, 0x28])), (Found::Once(2), Found::Once(4)));
    assert_eq!(decode_hex("00fF7a"), Some(vec![0x00, 0xff, 0x7a]));
    assert_eq!((decode_hex("0"), decode_hex("0g"), decode_hex("")), (None, None, Some(Vec::new())));
}

/// A text spliced reads as the draft will once the edit lands.
///
/// The bytes at a place give way to others: every byte and every gap past
/// it moves by the difference, the positions with them, so a text found
/// before the splice is found where it now stands and a gap is still named
/// by what it is; a stretch left with no byte is a stretch no longer, the
/// gaps either side of it side by side; and a splice no stretch holds
/// changes nothing (the mutants that move no gap, keep an emptied stretch,
/// or leave the text open past one answer another ordinal, or another
/// kind).
#[test]
fn a_text_spliced_reads_as_the_draft_will_once_the_edit_lands() {
    let mut text = text_of(json!([{"content": "alpha "}, {"atom": "v"}, {"content": "beta gamma"}, {"withheld": {"origin": "1.0.1.0.9", "width": "5"}}, {"content": "delta"}]));
    assert_eq!((text.positions(), text.find(b"beta"), text.find(b"delta")), (27, Found::Once(8), Found::Once(23)));
    text.splice(8, 4, b"be");
    assert_eq!((text.positions(), text.find(b"be"), text.find(b"gamma"), text.find(b"delta")), (25, Found::Once(8), Found::Once(11), Found::Once(21)));
    assert_eq!(text.find(b"alpha"), Found::Once(1), "what stands before the place stays");
    assert_eq!(text.find(b"gammadelta"), Found::Across { ordinal: 16, kind: "withheld".into() }, "the gap moved with the text after it, and is named still");
    assert_eq!(text.find(b"alpha be"), Found::Across { ordinal: 7, kind: "atom".into() }, "a gap before the place stays");
    text.splice(11, 5, b"gamma and more");
    assert_eq!((text.positions(), text.find(b"more"), text.find(b"delta")), (34, Found::Once(21), Found::Once(30)), "grown");
    assert_eq!(text.find(b"moredelta"), Found::Across { ordinal: 25, kind: "withheld".into() });
    text.splice(8, 17, b"");
    assert_eq!((text.positions(), text.find(b"delta"), text.stretches.len()), (17, Found::Once(13), 2), "the stretch between the two gaps is gone");
    assert_eq!(text.find(b"alpha delta"), Found::Across { ordinal: 7, kind: "atom".into() }, "the two gaps stand side by side, the atom first");
    assert_eq!(text.gaps.iter().map(|gap| (gap.ordinal, gap.kind.as_str())).collect::<Vec<_>>(), [(7, "atom"), (8, "withheld")]);
    text.splice(13, 5, b"");
    assert_eq!((text.positions(), text.find(b"delta"), text.stretches.len()), (12, Found::Nowhere, 1), "the last stretch emptied");
    text.push(&json!({"content": "tail"})).expect("text");
    assert_eq!((text.find(b"tail"), text.find(b"alpha tail")), (Found::Once(13), Found::Across { ordinal: 7, kind: "atom".into() }), "text read after it is a stretch of its own, past the gaps");
    let before = (text.bytes.clone(), text.stretches.clone(), text.gaps.clone(), text.positions());
    for (found, removed) in [(7, 1), (4, 9), (40, 1)] {
        text.splice(found, removed, b"x");
        assert_eq!((text.bytes.clone(), text.stretches.clone(), text.gaps.clone(), text.positions()), before, "{found}: no stretch holds the bytes");
    }
}

/// A text rearranged reads as the draft will once the cuts land.
///
/// Three cuts exchange the two regions between them and four the two outer
/// ones around the middle, as the wire's own examples over `abcde` have it;
/// what stands outside the cuts stays; a value that is no text goes with its
/// region, its positions with it and its kind kept; two runs of text a move
/// brings side by side are one stretch, so a word across the seam is found;
/// and any other count of cuts leaves the text as it reads (the mutants that
/// exchange the wrong pair, drop a gap's width, or leave two stretches side
/// by side answer another text, another ordinal or no match).
#[test]
fn a_text_rearranged_reads_as_the_draft_will_once_the_cuts_land() {
    let read = |text: &Text| String::from_utf8(text.bytes.clone()).expect("text");
    let abcde = text_of(json!([{"content": "abcde"}]));
    assert_eq!(read(&abcde.rearranged(&[2, 4, 6])), "adebc", "three cuts: wire.md's own example");
    assert_eq!(read(&abcde.rearranged(&[1, 2, 3, 4])), "cbade", "four cuts: wire.md's own example");
    assert_eq!(read(&abcde.rearranged(&[2, 3, 4])), "acbde", "what stands past the last cut stays");
    for cuts in [&[][..], &[2, 4][..], &[1, 2, 3, 4, 5][..]] {
        let same = abcde.rearranged(cuts);
        assert_eq!((read(&same), same.positions(), same.stretches.len()), ("abcde".to_string(), 5, 1), "{cuts:?}: no such rearrange");
    }
    let text = text_of(json!([{"content": "one\n"}, {"withheld": {"origin": "1.0.1.0.9", "width": "5"}}, {"content": "two\nthree\n"}, {"atom": "v"}, {"content": "four\n"}]));
    assert_eq!((text.positions(), text.find(b"three"), text.find(b"four")), (25, Found::Once(14), Found::Once(21)));
    // Line 2, the withheld run and `two`, moved to the end: [5, 14, 26).
    let moved = text.rearranged(&[5, 14, 26]);
    assert_eq!((moved.positions(), read(&moved)), (25, "one\nthree\nfour\ntwo\n".to_string()));
    assert_eq!(
        (moved.find(b"one\nthree"), moved.find(b"four"), moved.find(b"two")),
        (Found::Once(1), Found::Once(12), Found::Once(22)),
        "the text before the cuts and the text brought to it are one stretch"
    );
    assert_eq!(moved.gaps.iter().map(|gap| (gap.ordinal, gap.kind.as_str())).collect::<Vec<_>>(), [(11, "atom"), (17, "withheld")], "each gap with its region, its positions kept");
    assert_eq!(moved.find(b"four\ntwo"), Found::Across { ordinal: 17, kind: "withheld".into() }, "the withheld run stands before `two` still");
    assert_eq!(moved.stretches.len(), 3, "no two stretches side by side: {:?}", moved.stretches);
    // A cut inside a value that is no text tells it in two parts.
    let parted = text.rearranged(&[1, 7, 10]);
    assert_eq!((parted.positions(), parted.find(b"one"), parted.find(b"two")), (25, Found::Once(4), Found::Once(10)));
    assert_eq!(parted.gaps.iter().map(|gap| gap.ordinal).collect::<Vec<_>>(), [1, 8, 20], "three positions of the run, then two, then the atom");
}

/// A span set's content extent is read, and anything else is not one.
#[test]
fn a_span_sets_content_extent_is_read_and_anything_else_is_not_one() {
    assert_eq!(content_extent(&json!({"resp": "span_set", "set": []})), Some(0), "a registered-empty draft");
    assert_eq!(content_extent(&json!({"set": [{"start": "1.1", "width": "0.66"}]})), Some(66));
    assert_eq!(content_extent(&json!({"set": [{"start": "1.1", "width": "0.66"}, {"start": "2.1", "width": "0.3"}]})), Some(66), "content before links");
    assert_eq!(content_extent(&json!({"set": [{"start": "2.1", "width": "0.3"}]})), Some(0), "links alone");
    for unread in [json!({"resp": "rejected"}), json!({"set": [{"start": "1.1"}]}), json!({"set": [{"start": "1.1", "width": "0.x"}]}), json!({"set": "1.1"})] {
        assert_eq!(content_extent(&unread), None, "{unread}");
    }
}

// ── the edit, against a scripted board ──────────────────────────────────

/// A board answered from a script: each call's answer in order, each call
/// kept.
pub(super) struct Script {
    answers: RefCell<VecDeque<Result<Value, Refusal>>>,
    pub(super) sent: RefCell<Vec<Value>>,
    /// The key the session signs under, as a feed row names it; none for a
    /// session holding no key.
    pub(super) key: Option<String>,
}

/// The fingerprint of the key the scripted session signs under.
pub(super) fn own_key() -> String {
    "ab".repeat(32)
}

impl Script {
    /// Returns a board that answers its calls with `answers`, in order,
    /// under a session signing with [`own_key`].
    pub(super) fn of(answers: Vec<Result<Value, Refusal>>) -> Script {
        Script { answers: RefCell::new(answers.into()), sent: RefCell::new(Vec::new()), key: Some(own_key()) }
    }

    /// Keeps `call` and answers it with the script's next answer.
    fn next(&self, call: Value) -> Result<Value, Refusal> {
        let answer = self.answers.borrow_mut().pop_front().unwrap_or_else(|| panic!("the script holds no answer for {call}"));
        self.sent.borrow_mut().push(call);
        answer
    }

    /// Returns the calls made past the first `skip`, the script's every
    /// answer spent.
    pub(super) fn sent_past(&self, skip: usize) -> Vec<Value> {
        assert!(self.answers.borrow().is_empty(), "every scripted answer was asked for: {:?}", self.answers.borrow());
        self.sent.borrow()[skip..].to_vec()
    }
}

impl Calls for Script {
    fn op(&self, frame: Value) -> Result<Value, Refusal> {
        self.next(frame)
    }

    fn held(&self) -> Result<Value, Refusal> {
        self.next(json!({"call": "held"}))
    }

    fn drop_held(&self, held: u64) -> Result<Value, Refusal> {
        self.next(json!({"call": "drop", "held": held}))
    }

    fn changes(&self, doc: &str, since: u64) -> Result<Value, Refusal> {
        self.next(feed_read(doc, since))
    }

    fn key(&self) -> Option<String> {
        self.key.clone()
    }
}

/// The scripted call a read of the change feed under `doc` past `since` is
/// kept as.
pub(super) fn feed_read(doc: &str, since: u64) -> Value {
    json!({"call": "changes", "doc": doc, "since": since})
}

/// A page of the change feed whose first entry is a row of `op` at `at`
/// under the key `key`.
pub(super) fn feed_page(op: &str, key: &str, at: u64) -> Result<Value, Refusal> {
    Ok(json!({"entries": [{"at": at, "position": at, "op": op, "docs": [DOC], "key": key, "class": "drafts"}], "next": at, "head": at}))
}

/// An answer lost once the request left: the write may have landed.
pub(super) fn lost() -> Refusal {
    Refusal::Unreachable(DialError::Timeout("no answer".into()))
}

/// The board's verdict `code` on an `edit`, as the `op` row refuses with it.
pub(super) fn refused_edit(code: &str) -> Refusal {
    let body = json!({"resp": "rejected", "op": "edit", "code": code, "disposition": "permanent"});
    Refusal::Board(Refused { status: 200, code: code.into(), detail: None, op: Some("edit".into()), body })
}

/// Returns a sent `edit` frame less its `id`, the `id` checked: the shell's
/// own, drawn for the call.
pub(super) fn less_id(frame: &Value) -> Value {
    let mut frame = frame.clone();
    let id = frame.as_object_mut().expect("a frame").remove("id").expect("an `id` on the call's one write");
    assert!(id.as_str().is_some_and(|id| DialId::parse(id).is_some()), "the shell's own id: {id}");
    frame
}

/// The one `edit` frame of `changes` typed against the scripted read.
pub(super) fn edit_frame(changes: &[Value]) -> Value {
    frames::edit(DOC, changes, READ_AT, None)
}

/// The position the scripted draft is read at.
pub(super) const READ_AT: u64 = 40;

/// The address the scripted insert mints its first byte at.
pub(super) const MINTED: &str = "1.0.1.0.64.0.1.80";

/// The three reads every scripted edit of [`CODE`] opens with, answered.
///
/// The delivery's `as_of` is past the extent's: a commit elsewhere on the
/// board landed between the two reads.
pub(super) fn reads_of(text: &str) -> Vec<Result<Value, Refusal>> {
    vec![
        Ok(json!({"resp": "doc_metadata", "doc": DOC, "published": false, "as_of": READ_AT - 1})),
        Ok(json!({"resp": "span_set", "as_of": READ_AT, "set": [{"start": "1.1", "width": format!("0.{}", text.len())}]})),
        Ok(json!({"resp": "delivery", "as_of": READ_AT + 2, "items": [{"content": text}]})),
    ]
}

/// The frames of [`reads_of`]'s three reads.
pub(super) fn read_frames(text: &str) -> Vec<Value> {
    vec![frames::doc_metadata(DOC), frames::span_set(DOC), frames::retrieve_v(DOC, 1, text.len() as u64)]
}

/// Returns the edit `text.replace` makes of `args` through `calls`: its
/// members read as the row reads them, then the edit made.
fn replace_text(calls: &impl Calls, args: &Value) -> Result<Answer, Refusal> {
    replace(calls, Asked::read(args)?)
}

/// Returns the edit's outcome over a board answering `after` past the three
/// reads of [`CODE`], and the calls made past them.
fn edit(old: &str, new: &str, after: Vec<Result<Value, Refusal>>) -> (Result<Answer, Refusal>, Vec<Value>) {
    let script = Script::of(reads_of(CODE).into_iter().chain(after).collect());
    let args = json!({"doc": DOC, "old": old, "new": new});
    let outcome = replace_text(&script, &args);
    assert_eq!(script.sent.borrow()[..3], read_frames(CODE)[..], "the three reads, in order");
    (outcome, script.sent_past(3))
}

/// A held answer, as the shell's `op` row gives a burst it holds.
pub(super) fn held_answer(held: u64, cause: &str) -> Result<Value, Refusal> {
    Ok(json!({"resp": "held", "held": held, "cause": cause}))
}

/// The board's verdict on a write typed against an older state.
pub(super) fn moved_verdict(op: &str, as_of: u64, current: u64) -> Value {
    json!({"resp": "rejected", "op": op, "code": "arrangement_moved", "disposition": "permanent", "site": {"as_of": as_of, "current": current}})
}

/// The `held` row's answer listing line `held` with `refusal` beside it.
pub(super) fn lines(held: u64, cause: &str, refusal: Value) -> Result<Value, Refusal> {
    Ok(json!([{"held": held + 7, "doc": "1.0.1.0.65", "cause": "moved", "refusal": moved_verdict("insert", 1, 2)}, {"held": held, "doc": DOC, "cause": cause, "sent": false, "refusal": refusal}]))
}

/// The two calls that settle a held line: the list, then the drop.
pub(super) fn settling(held: u64) -> Vec<Value> {
    vec![json!({"call": "held"}), json!({"call": "drop", "held": held})]
}

/// An edit is one frame of one change, typed against the first read.
///
/// An edit that only inserts, one that only removes and one that does both
/// each send ONE `edit` frame of one change — the old bytes' positions and
/// the new bytes in their place — under an `id` of the shell's own, typed
/// against the `as_of` of the read the extent came from, though a later read
/// of the same call answered a later position. No image is read and nothing
/// follows the frame: a replacement is one commit, no state standing
/// between its removal and its insert (the mutant that sends the insert and
/// then the removal sends two frames, and the one that types the write
/// against a read made just before it sends that read's position).
#[test]
fn an_edit_is_one_frame_of_one_change_typed_against_the_first_read() {
    let word = ordinal_of(CODE, "add");
    let (answer, sent) = edit("add(", "addition(", vec![Ok(json!({"resp": "ack_addr", "addr": MINTED, "at": 44, "committed": true}))]);
    assert_eq!(sent.iter().map(less_id).collect::<Vec<_>>(), [edit_frame(&[frames::minted(word + 3, 0, "ition")])]);
    assert_eq!(
        answer.expect("an answer"),
        Answer { value: json!({"outcome": "replaced", "doc": DOC, "ordinal": (word + 3).to_string(), "removed": "0", "inserted": "5", "addr": MINTED, "at": 44}), is_error: false }
    );
    let (answer, sent) = edit("total = add", "add", vec![Ok(json!({"resp": "ack", "at": 45}))]);
    assert_eq!(sent.iter().map(less_id).collect::<Vec<_>>(), [edit_frame(&[frames::minted(ordinal_of(CODE, "total"), 8, "")])]);
    assert_eq!(
        answer.expect("an answer"),
        Answer { value: json!({"outcome": "replaced", "doc": DOC, "ordinal": ordinal_of(CODE, "total").to_string(), "removed": "8", "inserted": "0", "at": 45}), is_error: false }
    );
    let (answer, sent) = edit("add", "subtract", vec![Ok(json!({"resp": "ack_addr", "addr": MINTED, "at": 46, "committed": true}))]);
    assert_eq!(sent.iter().map(less_id).collect::<Vec<_>>(), [edit_frame(&[frames::minted(word, 3, "subtract")])], "one frame: the three old bytes removed and the eight new minted in one change");
    assert_eq!(
        answer.expect("an answer"),
        Answer { value: json!({"outcome": "replaced", "doc": DOC, "ordinal": word.to_string(), "removed": "3", "inserted": "8", "addr": MINTED, "at": 46}), is_error: false }
    );
    assert!(sent.iter().all(|frame| frame["op"] == "edit"), "no image read and no burst: {sent:?}");
}

/// The same text for old and new is found, and nothing is written.
#[test]
fn the_same_text_for_old_and_new_is_found_and_nothing_is_written() {
    let (answer, sent) = edit("add", "add", Vec::new());
    assert!(sent.is_empty());
    assert_eq!(answer.expect("an answer"), Answer { value: json!({"outcome": "unchanged", "doc": DOC, "ordinal": ordinal_of(CODE, "add").to_string(), "as_of": READ_AT}), is_error: false });
    let (answer, _) = edit("subtract", "subtract", Vec::new());
    assert_eq!(answer.expect("an answer").value["cause"], "not_found", "a text the draft does not hold is not found, though it would change nothing");
}

/// A refusal a read decides is answered before any write.
///
/// A text that stands nowhere, twice, or only across an atom, and a changed
/// text past one insert's cap, are each refused as data with the position
/// the draft was read at, and no write is sent.
#[test]
fn a_refusal_a_read_decides_is_answered_before_any_write() {
    let refused = |old: &str, new: &str, detail: Value| {
        let (answer, sent) = edit(old, new, Vec::new());
        assert!(sent.is_empty(), "no write: {sent:?}");
        let mut expected = json!({"outcome": "refused", "doc": DOC});
        expected.as_object_mut().expect("an object").extend(detail.as_object().expect("an object").clone());
        assert_eq!(answer.expect("an answer"), Answer { value: expected, is_error: false });
    };
    refused("subtract", "add", json!({"cause": "not_found", "count": 0, "as_of": READ_AT}));
    refused("total", "sum", json!({"cause": "not_unique", "count": 2, "as_of": READ_AT}));
    refused("fn", &format!("fn{}", "x".repeat(MAX_NEW_BYTES + 1)), json!({"cause": "too_large", "what": "new", "bytes": (MAX_NEW_BYTES + 1).to_string(), "cap": MAX_NEW_BYTES.to_string()}));
    let with_an_atom = vec![
        Ok(json!({"resp": "doc_metadata", "doc": DOC, "published": false})),
        Ok(json!({"resp": "span_set", "as_of": READ_AT, "set": [{"start": "1.1", "width": "0.5"}]})),
        Ok(json!({"resp": "delivery", "as_of": READ_AT, "items": [{"content": "ab"}, {"atom": "v"}, {"content": "cd"}]})),
    ];
    let script = Script::of(with_an_atom);
    let answer = replace_text(&script, &json!({"doc": DOC, "old": "bc", "new": "x"})).expect("an answer");
    assert_eq!(answer, Answer { value: json!({"outcome": "refused", "cause": "crosses_atom", "doc": DOC, "ordinal": "3", "kind": "atom", "as_of": READ_AT}), is_error: false });
    assert_eq!(script.sent_past(3), Vec::<Value>::new());
}

/// A published document is refused at the first read.
///
/// The one call made is the read that says it is published: none of its
/// text is read and nothing is written (the mutant that does not ask reads
/// on and writes).
#[test]
fn a_published_document_is_refused_at_the_first_read() {
    let script = Script::of(vec![Ok(json!({"resp": "doc_metadata", "doc": "1.0.1.0.7", "published": true}))]);
    let answer = replace_text(&script, &json!({"doc": "1.0.1.0.7.2", "old": "a", "new": "b"})).expect("an answer");
    assert_eq!(answer, Answer { value: json!({"outcome": "refused", "cause": "published", "doc": "1.0.1.0.7.2", "published": "1.0.1.0.7"}), is_error: false });
    assert_eq!(script.sent_past(0), [frames::doc_metadata("1.0.1.0.7.2")]);
}

/// A member of the wrong form is refused before any call.
#[test]
fn a_member_of_the_wrong_form_is_refused_before_any_call() {
    for (args, what) in [
        (json!({"old": "a", "new": "b"}), "doc"),
        (json!({"doc": 7, "old": "a", "new": "b"}), "doc"),
        (json!({"doc": "1..2", "old": "a", "new": "b"}), "doc"),
        (json!({"doc": "01.0.1", "old": "a", "new": "b"}), "doc"),
        (json!({"doc": DOC, "new": "b"}), "old"),
        (json!({"doc": DOC, "old": "", "new": "b"}), "old"),
        (json!({"doc": DOC, "old": ["a"], "new": "b"}), "old"),
        (json!({"doc": DOC, "old": "a"}), "new"),
        (json!({"doc": DOC, "old": "a", "new": null}), "new"),
    ] {
        let script = Script::of(Vec::new());
        let refusal = replace_text(&script, &args).expect_err("a refusal");
        assert_eq!(refusal.to_value(), Refusal::malformed(what).to_value(), "{args}");
        assert!(script.sent_past(0).is_empty());
    }
}

/// A write the board refuses is answered with its verdict, nothing written.
///
/// The board refuses the frame as typed against an older state, or for any
/// other cause: the edit answers the verdict as data, its cause the board's
/// code and the verdict under `refusal`, and sends nothing more — a verdict
/// is the board's judgment of the frame, never an answer lost, so the frame
/// is not asked again and no feed is read.
#[test]
fn a_write_the_board_refuses_is_answered_with_its_verdict() {
    for code in ["arrangement_moved", "not_owner", "withheld"] {
        let refusal = refused_edit(code);
        let Refusal::Board(Refused { body: verdict, .. }) = refusal.clone() else { unreachable!() };
        let (answer, sent) = edit("add", "subtract", vec![Err(refusal)]);
        assert_eq!(sent.len(), 1, "{code}: the one frame, never asked again");
        assert_eq!(answer.expect("an answer"), Answer { value: json!({"outcome": "refused", "cause": code, "doc": DOC, "refusal": verdict}), is_error: false }, "{code}");
    }
}

/// A lost answer is asked again once, the same frame under the same `id`.
///
/// The frame's answer is lost once the request left, so it may have landed:
/// the same frame is sent again, byte for byte, its `id` and the position it
/// is typed against unchanged, and the board's answer to it — its memo's
/// acknowledgment where it applied the first, a first landing where it never
/// met it — is the edit's, addresses and all. An answer that left nothing
/// sent is no lost answer, and is the call's refusal with nothing asked
/// again (the mutants that never ask again, that ask again under a fresh
/// `id`, and that type the re-ask against a later state, which lands a
/// second time what the first landed).
#[test]
fn a_lost_answer_is_asked_again_once_under_the_same_id() {
    let word = ordinal_of(CODE, "add");
    let (answer, sent) = edit("add", "subtract", vec![Err(lost()), Ok(json!({"resp": "ack_addr", "addr": MINTED, "at": 44, "committed": true}))]);
    assert_eq!(sent.len(), 2, "the frame and its one re-ask");
    assert_eq!(sent[0], sent[1], "the same frame: its id and its typed position unchanged");
    assert_eq!(less_id(&sent[0]), edit_frame(&[frames::minted(word, 3, "subtract")]));
    assert_eq!(answer.expect("an answer").value, json!({"outcome": "replaced", "doc": DOC, "ordinal": word.to_string(), "removed": "3", "inserted": "8", "addr": MINTED, "at": 44}));
    let unsent = || Refusal::Unreachable(DialError::Connect("refused".into()));
    let (outcome, sent) = edit("add", "subtract", vec![Err(unsent())]);
    assert_eq!((outcome.expect_err("the refusal").to_value(), sent.len()), (unsent().to_value(), 1), "a request that never left landed nothing");
}

/// A lost answer its re-ask does not settle is settled from the change feed.
///
/// The frame's answer is lost, and the re-ask's too — or the re-ask is
/// refused as typed against an older state, the board's memo gone at a
/// restart and the draft moved by the frame's own commit, or the shell
/// refuses to send it. The draft's first row past the typed position is
/// read: an `edit` under the session's own key is the frame's own commit,
/// and the edit answers landed at that row's position, the address its
/// acknowledgment named unread — never refused for its own effect (the
/// mutant that answers the re-ask's `arrangement_moved` as the edit's
/// refusal says nothing was written of an edit that stands).
#[test]
fn a_lost_answer_the_re_ask_does_not_settle_is_read_off_the_change_feed() {
    let word = ordinal_of(CODE, "add");
    let stopped = || Refusal::shell(Name::STOPPED, json!({"op": "edit"}));
    for again in [refused_edit("arrangement_moved"), lost(), stopped()] {
        let (answer, sent) = edit("add", "subtract", vec![Err(lost()), Err(again.clone()), feed_page("edit", &own_key(), 47)]);
        assert_eq!(sent.len(), 3, "{again}: the frame, its re-ask, the feed's read");
        assert_eq!((sent[0] == sent[1], &sent[2]), (true, &feed_read(DOC, READ_AT)), "{again}: the feed read under the draft past the typed position");
        assert_eq!(
            answer.expect("an answer"),
            Answer { value: json!({"outcome": "replaced", "doc": DOC, "ordinal": word.to_string(), "removed": "3", "inserted": "8", "at": 47}), is_error: false },
            "{again}: landed at its own row's position, no address named"
        );
    }
}

/// A lost answer no row settles is `answer_lost`, naming the typed position.
///
/// The draft's first row past the typed position is another writer's, or the
/// session's own of another kind; the feed names no row, or names one with
/// no position; its read is refused; or the session holds no key, so no row
/// is its own. Each leaves the edit unsettled: the answer is `answer_lost`,
/// an error naming `as_of`, the position the frame was typed against, and
/// what lost the answer — no verdict on the edit — and nothing is sent after
/// the read (the mutants that read any row of the session's key, or any
/// `edit` row, as the frame's own answer an edit that never landed as
/// landed).
#[test]
fn a_lost_answer_no_row_settles_is_answer_lost_naming_the_typed_position() {
    let unsettled = |feed: Option<Result<Value, Refusal>>, key: Option<String>, what: &str| {
        let after = [Err(lost()), Err(refused_edit("arrangement_moved"))].into_iter().chain(feed.clone());
        let mut script = Script::of(reads_of(CODE).into_iter().chain(after).collect());
        script.key = key;
        let answer = replace_text(&script, &json!({"doc": DOC, "old": "add", "new": "subtract"})).expect("an answer");
        let sent = script.sent_past(3);
        assert_eq!(sent.len(), 2 + usize::from(feed.is_some()), "{what}: nothing sent after the read");
        let value = json!({"outcome": "answer_lost", "doc": DOC, "as_of": READ_AT, "cause": "unreachable", "refusal": lost().to_value()});
        assert_eq!(answer, Answer { value, is_error: true }, "{what}");
        crate::shapes::assert_declared("TextAnswerLost", &answer.into_value());
    };
    let other = "cd".repeat(32);
    unsettled(Some(feed_page("edit", &other, 47)), Some(own_key()), "another writer's edit");
    unsettled(Some(feed_page("edit", "bare", 47)), Some(own_key()), "a bare session's edit");
    unsettled(Some(feed_page("insert", &own_key(), 47)), Some(own_key()), "the session's own write of another kind");
    unsettled(Some(Ok(json!({"entries": [], "next": READ_AT, "head": READ_AT}))), Some(own_key()), "no row past the typed position");
    unsettled(Some(Ok(json!({"entries": [{"op": "edit", "key": own_key()}], "next": READ_AT, "head": READ_AT}))), Some(own_key()), "a row naming no position");
    unsettled(Some(Err(lost())), Some(own_key()), "a feed read the board does not answer");
    unsettled(None, None, "a session holding no key, no row its own: the feed is not read");
}

/// A re-ask refused for another cause is the edit's refusal.
///
/// The frame's answer is lost and its re-ask is judged afresh and refused
/// for a cause that is not the draft having moved: the verdict is the
/// frame's, and the edit answers it as data, no feed read.
#[test]
fn a_re_ask_refused_for_another_cause_is_the_edits_refusal() {
    let refusal = refused_edit("not_owner");
    let Refusal::Board(Refused { body: verdict, .. }) = refusal.clone() else { unreachable!() };
    let (answer, sent) = edit("add", "subtract", vec![Err(lost()), Err(refusal)]);
    assert_eq!(sent.len(), 2, "the frame and its re-ask: no feed read");
    assert_eq!(answer.expect("an answer"), Answer { value: json!({"outcome": "refused", "cause": "not_owner", "doc": DOC, "refusal": verdict}), is_error: false });
}

/// A refusal of a read is the call's refusal, and the shell's of the write.
#[test]
fn a_refusal_of_a_read_or_the_shells_of_the_write_is_the_calls_refusal() {
    let withheld = || Refusal::Board(Refused { status: 200, code: "withheld".into(), detail: None, op: Some("doc_metadata".into()), body: json!({"resp": "rejected", "code": "withheld"}) });
    let script = Script::of(vec![Err(withheld())]);
    let refusal = replace_text(&script, &json!({"doc": DOC, "old": "a", "new": "b"})).expect_err("the read's refusal");
    assert_eq!(refusal.to_value(), withheld().to_value());
    for at in 1..3 {
        let mut answers = reads_of(CODE);
        answers.truncate(at);
        answers.push(Err(Refusal::shell(Name::SESSION_ENDED, json!({"session": "s-1"}))));
        let script = Script::of(answers);
        let refusal = replace_text(&script, &json!({"doc": DOC, "old": "add", "new": "sub"})).expect_err("the read's refusal");
        assert_eq!(refusal.name(), "session_ended", "read {at}");
    }
    for name in [Name::ANOTHER_WINDOW, Name::STOPPED, Name::HELD_LINES] {
        let (outcome, sent) = edit("add", "subtract", vec![Err(Refusal::shell(name, json!({"op": "edit"})))]);
        assert_eq!((outcome.expect_err("the write's refusal").name(), sent.len()), (name.as_str(), 1), "the shell's refusal of the write: nothing written, nothing asked again");
    }
}

/// An answer the adapter does not read is never taken for a draft's.
///
/// A metadata answer that says neither published nor draft, an extent with
/// no position or no span set, and a delivery with no items are each
/// refused `unread`, `isError`, naming the read — never read as a draft, an
/// empty one, or a text that holds no match (SP-14) — and a delivery item
/// whose positions cannot be counted is refused naming its kind.
#[test]
fn an_answer_the_adapter_does_not_read_is_never_taken_for_a_drafts() {
    let run = |answers: Vec<Result<Value, Refusal>>| {
        let script = Script::of(answers);
        let answer = replace_text(&script, &json!({"doc": DOC, "old": "add", "new": "sub"})).expect("an answer");
        assert!(script.sent_past(0).iter().all(|call| !["insert", "delete", "edit"].contains(&call["op"].as_str().unwrap_or_default())), "no write");
        answer
    };
    let unread = |op: &str| Answer { value: json!({"outcome": "refused", "cause": "unread", "doc": DOC, "op": op}), is_error: true };
    assert_eq!(run(vec![Ok(json!({"resp": "doc_metadata", "doc": DOC}))]), unread("doc_metadata"));
    assert_eq!(run(vec![Ok(json!({"resp": "doc_metadata", "published": "no"}))]), unread("doc_metadata"));
    let draft = || Ok(json!({"resp": "doc_metadata", "doc": DOC, "published": false}));
    assert_eq!(run(vec![draft(), Ok(json!({"resp": "span_set", "set": []}))]), unread("retrieve_doc_v_span_set"));
    assert_eq!(run(vec![draft(), Ok(json!({"resp": "span_set", "as_of": 4}))]), unread("retrieve_doc_v_span_set"));
    let extent = |n: u64| Ok(json!({"resp": "span_set", "as_of": READ_AT, "set": [{"start": "1.1", "width": format!("0.{n}")}]}));
    assert_eq!(run(vec![draft(), extent(3), Ok(json!({"resp": "delivery", "as_of": READ_AT}))]), unread("retrieve_v"));
    let uncounted = run(vec![draft(), extent(3), Ok(json!({"resp": "delivery", "items": [{"content": "ab"}, {"future": {"origin": "1.0.9"}}]}))]);
    assert_eq!(uncounted, Answer { value: json!({"outcome": "refused", "cause": "unknown_item", "doc": DOC, "kind": "future"}), is_error: false });
    let empty = run(vec![draft(), Ok(json!({"resp": "span_set", "as_of": READ_AT, "set": []}))]);
    assert_eq!(empty.value, json!({"outcome": "refused", "cause": "not_found", "doc": DOC, "count": 0, "as_of": READ_AT}), "an empty draft is read, and holds no match");
}

/// A draft past one delivery is read in parts, typed against the first read.
///
/// Each part asks the delivery budget's positions, the last what is left;
/// the edge runs a part boundary cut arrive as hex and are one stretch; and
/// a word past the boundary is written at its own ordinal, typed against
/// the extent's read. Parts that hold other than the extent's positions are
/// a draft that changed between the reads, refused with nothing written;
/// and a draft past the cap is refused before any part is read.
#[test]
fn a_draft_past_one_delivery_is_read_in_parts_typed_against_the_first_read() {
    let budget = READ_POSITIONS as usize;
    let text = format!("{}é\nlet word = 1;\n", "a".repeat(budget - 1));
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let extent = |n: u64| Ok(json!({"resp": "span_set", "as_of": READ_AT, "set": [{"start": "1.1", "width": format!("0.{n}")}]}));
    let draft = || Ok(json!({"resp": "doc_metadata", "doc": DOC, "published": false}));
    let parts = || {
        vec![
            Ok(json!({"resp": "delivery", "as_of": READ_AT + 1, "items": [{"hex": hex(&text.as_bytes()[..budget])}]})),
            Ok(json!({"resp": "delivery", "as_of": READ_AT + 2, "items": [{"hex": hex(&text.as_bytes()[budget..])}]})),
        ]
    };
    let script = Script::of([vec![draft(), extent(text.len() as u64)], parts(), vec![Ok(json!({"resp": "ack_addr", "addr": MINTED, "at": 60, "committed": true}))]].concat());
    let answer = replace_text(&script, &json!({"doc": DOC, "old": "let word", "new": "let name"})).expect("an answer");
    let word = ordinal_of(&text, "word");
    assert_eq!(answer.value, json!({"outcome": "replaced", "doc": DOC, "ordinal": word.to_string(), "removed": "4", "inserted": "4", "addr": MINTED, "at": 60}));
    let rest = text.len() as u64 - READ_POSITIONS;
    let sent = script.sent_past(2);
    assert_eq!(sent[..2], [frames::retrieve_v(DOC, 1, READ_POSITIONS), frames::retrieve_v(DOC, READ_POSITIONS + 1, rest)]);
    assert_eq!(sent[2..].iter().map(less_id).collect::<Vec<_>>(), [edit_frame(&[frames::minted(word, 4, "name")])]);
    let script = Script::of([vec![draft(), extent(text.len() as u64 + 1)], parts()].concat());
    let answer = replace_text(&script, &json!({"doc": DOC, "old": "let word", "new": "let name"})).expect("an answer");
    assert_eq!(
        answer,
        Answer { value: json!({"outcome": "refused", "cause": "arrangement_moved", "doc": DOC, "as_of": READ_AT}), is_error: false },
        "the parts hold one position fewer than the extent named"
    );
    let script = Script::of(vec![draft(), extent(MAX_DRAFT_POSITIONS + 1)]);
    let answer = replace_text(&script, &json!({"doc": DOC, "old": "a", "new": "b"})).expect("an answer");
    assert_eq!(
        answer,
        Answer {
            value: json!({"outcome": "refused", "cause": "too_large", "doc": DOC, "what": "draft", "positions": (MAX_DRAFT_POSITIONS + 1).to_string(), "cap": MAX_DRAFT_POSITIONS.to_string()}),
            is_error: false
        }
    );
    assert_eq!(script.sent_past(0).len(), 2, "no part of the text is read");
    assert_eq!(MAX_DRAFT_POSITIONS, 64 * MAX_DELIVERY_ITEMS, "the cap is sixty-four reads of the delivery budget");
}

// ── the edit through the shell's rows ──────────────────────────────────

/// A board answering an edit's rows from a script: each call kept with the
/// row and the session it named, the sessions that stand given.
pub(super) struct Rowed {
    answers: RefCell<VecDeque<Result<Value, Refusal>>>,
    named: RefCell<Vec<(Row, String)>>,
    standing: Vec<&'static str>,
}

impl Rowed {
    /// Returns a board answering with `answers`, in order, at which the
    /// sessions `standing` stand.
    pub(super) fn of(answers: Vec<Result<Value, Refusal>>, standing: Vec<&'static str>) -> Rowed {
        Rowed { answers: RefCell::new(answers.into()), named: RefCell::new(Vec::new()), standing }
    }

    /// Returns the sessions the calls named, in order, the script spent.
    pub(super) fn sessions(&self) -> Vec<String> {
        assert!(self.answers.borrow().is_empty(), "every scripted answer was asked for: {:?}", self.answers.borrow());
        self.named.borrow().iter().map(|(_, session)| session.clone()).collect()
    }
}

impl Rows for Rowed {
    fn answer(&self, row: Row, args: &Value) -> Result<Value, Refusal> {
        self.named.borrow_mut().push((row, args["session"].as_str().unwrap_or_default().to_string()));
        self.answers.borrow_mut().pop_front().unwrap_or_else(|| panic!("the script holds no answer for {row:?} {args}"))
    }

    fn stands(&self, session: &str) -> bool {
        self.standing.contains(&session)
    }

    fn key(&self, _: &str) -> Option<String> {
        Some(own_key())
    }
}

/// The death of `s-1`, the restart arm having re-opened `reopened` where it
/// names one.
pub(super) fn died(reopened: Option<&str>) -> Result<Value, Refusal> {
    let reason = match reopened {
        Some(session) => json!({"arm": "restart", "reopened": true, "session": session}),
        None => json!({"arm": "restart", "reopened": false}),
    };
    Err(Refusal::shell(Name::SESSION_DIED, json!({"session": "s-1", "reason": reason})))
}

/// Returns the edit of `add` into `addition` through `rows`, under `s-1`.
fn through(rows: &Rowed) -> Result<Answer, Refusal> {
    replace(&Under::new(rows, "s-1"), Asked { doc: DOC, old: "add", new: "addition" })
}

/// A call that meets a death the restart arm re-opened is made again under
/// the re-open, and the edit stands under it from then on.
///
/// The draft's first read meets the death: it is made once more under `s-2`,
/// which stands, and every later call names `s-2`, the edit landing as one
/// no death met; a death naming a re-open that does not stand, or none, is
/// the call's refusal, nothing written; and a second death of the same call
/// is answered as it stands, never followed again (the mutants that answer
/// every death, follow a re-open no session stands under, go back to the
/// dead session, or follow without end).
#[test]
fn a_call_that_meets_a_death_the_restart_arm_re_opened_is_made_again_under_the_re_open() {
    let ack = || Ok(json!({"resp": "ack_addr", "addr": MINTED, "at": 44, "committed": true}));
    let rows = Rowed::of([vec![died(Some("s-2"))], reads_of(CODE), vec![ack()]].concat(), vec!["s-2"]);
    let answer = through(&rows).expect("an answer");
    assert_eq!(answer.value["outcome"], "replaced", "{}", answer.value);
    assert_eq!(rows.sessions(), ["s-1", "s-2", "s-2", "s-2", "s-2"], "the read made again under the re-open, every call after it under it too");
    for (reopened, standing) in [(Some("s-2"), vec![]), (None, vec!["s-2"])] {
        let rows = Rowed::of(vec![died(reopened)], standing);
        assert_eq!(through(&rows), Err(died(reopened).unwrap_err()), "{reopened:?}: the death is the call's refusal");
        assert_eq!(rows.sessions(), ["s-1"]);
    }
    let second = || Err(Refusal::shell(Name::SESSION_DIED, json!({"session": "s-2", "reason": {"arm": "restart", "reopened": true, "session": "s-3"}})));
    let rows = Rowed::of(vec![died(Some("s-2")), second()], vec!["s-2", "s-3"]);
    assert_eq!(through(&rows), Err(second().unwrap_err()), "a second death is answered as it stands");
    assert_eq!(rows.sessions(), ["s-1", "s-2"]);
}

/// A lost answer's re-ask that meets the session's death is made under the
/// re-open, and the feed is read under it.
///
/// The board restarted between the frame and its re-ask: the re-ask meets
/// the death, is made once more under the session the restart arm re-opened,
/// and is refused there as typed against an older state, the board's memo
/// gone with its session; the feed's read then names the re-open, and the
/// frame's own row — the key the same under both sessions — is the edit's
/// landing.
#[test]
fn a_re_ask_that_meets_the_sessions_death_is_made_and_settled_under_the_re_open() {
    let after = vec![Err(lost()), died(Some("s-2")), Err(refused_edit("arrangement_moved")), feed_page("edit", &own_key(), 47)];
    let rows = Rowed::of([reads_of(CODE), after].concat(), vec!["s-2"]);
    let answer = through(&rows).expect("an answer");
    assert_eq!((&answer.value["outcome"], &answer.value["at"], answer.value.get("addr")), (&json!("replaced"), &json!(47), None), "{}", answer.value);
    assert_eq!(rows.named.borrow().iter().skip(3).map(|(row, _)| *row).collect::<Vec<_>>(), [Row::Op, Row::Op, Row::Op, Row::Changes]);
    assert_eq!(rows.sessions()[3..], ["s-1", "s-1", "s-2", "s-2"], "the re-ask made again under the re-open, the feed read under it");
}

/// An error answer carries the error member, and a data answer none.
///
/// The row's answer is the edit's object, `error: true` set in it exactly
/// where the edit's answer is an error — a read it does not read, an answer
/// lost that no read settled — and nothing beside it in every other (the
/// mutants that set the member on every answer, on none, or as another
/// value).
#[test]
fn an_error_answer_carries_the_error_member_and_a_data_answer_none() {
    let data = json!({"outcome": "refused", "cause": "not_found", "doc": DOC, "count": 0, "as_of": READ_AT});
    assert_eq!(Answer::data(data.clone()).into_value(), data, "data stands as the edit built it");
    let (answer, _) = edit("add", "addition", vec![Err(lost()), Err(lost()), Ok(json!({"entries": []}))]);
    assert_eq!(answer.expect("an answer").into_value(), json!({"outcome": "answer_lost", "doc": DOC, "as_of": READ_AT, "cause": "unreachable", "refusal": lost().to_value(), "error": true}));
    let (answer, _) = edit("add", "addition", vec![Err(refused_edit("arrangement_moved"))]);
    assert_eq!(answer.expect("an answer").into_value().get(ERROR), None, "the board's verdict is data");
    let (answer, _) = edit("add", "addition", vec![Ok(json!({"resp": "ack_addr", "addr": MINTED, "at": 44, "committed": true}))]);
    assert_eq!(answer.expect("an answer").into_value().get(ERROR), None, "a landing is data");
}

/// A halt naming a file the edit met and is not answered with is the row's
/// to say.
///
/// The read of the feed that settles a lost answer meets a halt about a
/// file: the edit answers `answer_lost`, and the halt is left for the row to
/// say on `Talk`, once, however often the edit met it; a halt the edit is
/// answered with is `Shell::call`'s to say, and the row leaves it; and a
/// halt naming no file is no one's to say (the mutants that keep no halt,
/// keep the one the call answers too, or keep one twice).
#[test]
fn a_halt_naming_a_file_the_edit_met_and_is_not_answered_with_is_the_rows_to_say() {
    let face = |path: Option<&str>| skep_client::halt::Face { state: "the key file does not read".into(), cause: "c".into(), act: "a".into(), path: path.map(Into::into) };
    let about_a_file = || Err(Refusal::named(Name::STORE_UNREADABLE, face(Some("/store/keys/k"))));
    let unsettled = vec![Err(lost()), Err(lost()), about_a_file()];
    let rows = Rowed::of([reads_of(CODE), unsettled].concat(), vec![]);
    let under = Under::new(&rows, "s-1");
    let answered = replace(&under, Asked { doc: DOC, old: "add", new: "subtract" });
    assert_eq!(answered.as_ref().map(|answer| answer.value["outcome"].clone()), Ok(json!("answer_lost")));
    assert_eq!(under.unsaid(&answered), [about_a_file().unwrap_err()], "the halt the feed's read met");
    let rows = Rowed::of(vec![about_a_file()], vec![]);
    let under = Under::new(&rows, "s-1");
    let answered = replace(&under, Asked { doc: DOC, old: "add", new: "subtract" });
    assert_eq!(answered, Err(about_a_file().unwrap_err()));
    assert!(under.unsaid(&answered).is_empty(), "the call's own refusal is the call's to say");
    let twice = Rowed::of(vec![about_a_file(), about_a_file()], vec![]);
    let under = Under::new(&twice, "s-1");
    assert!(under.op(json!({})).is_err() && under.op(json!({})).is_err());
    assert_eq!(under.unsaid(&Ok(Answer::data(json!({})))).len(), 1, "one halt met twice is said once");
    let pathless = Rowed::of(vec![Err(Refusal::named(Name::STORE_UNREADABLE, face(None)))], vec![]);
    let under = Under::new(&pathless, "s-1");
    assert!(under.op(json!({})).is_err());
    assert!(under.unsaid(&Ok(Answer::data(json!({})))).is_empty(), "a face naming no file has no path to say");
}

/// Times the find and the trim over texts of three sizes.
///
/// A text of about 2 KB, 40 KB and 200 KB of numbered lines is read from
/// one delivery item a part, a word on its middle line found and the edit
/// trimmed, `SKEP_MEASURE_RUNS` times (15 unless set): the medians are
/// printed, the reading of the items apart from the find and the trim.
#[test]
#[ignore = "measurement - run by hand"]
fn measure_the_find_and_the_trim() {
    let runs: usize = std::env::var("SKEP_MEASURE_RUNS").ok().and_then(|n| n.parse().ok()).unwrap_or(15);
    for bytes in [2 * 1024, 40 * 1024, 200 * 1024] {
        let mut text = String::new();
        let mut line = 0;
        while text.len() < bytes {
            text.push_str(&format!("    let value_{line:06} = compute({line:06});\n"));
            line += 1;
        }
        let parts: Vec<Value> = text.as_bytes().chunks(READ_POSITIONS as usize).map(|part| json!({"content": String::from_utf8_lossy(part)})).collect();
        let (old, new) = (format!("compute({:06})", line / 2), format!("combine({:06})", line / 2));
        let (mut reading, mut finding) = (Vec::new(), Vec::new());
        for _ in 0..runs {
            let began = Instant::now();
            let mut read = Text::default();
            for part in &parts {
                read.push(part).expect("text");
            }
            reading.push(began.elapsed());
            let began = Instant::now();
            let Found::Once(ordinal) = read.find(old.as_bytes()) else { panic!("the word stands once") };
            let edit = Edit::of(ordinal, &old, &new);
            finding.push(began.elapsed());
            assert_eq!((edit.removed, edit.inserted), (3, "bin"));
        }
        reading.sort_unstable();
        finding.sort_unstable();
        eprintln!(
            "{} bytes in {} parts: the items read into the text in {:.3} ms, the find and the trim in {:.3} ms (medians of {runs})",
            text.len(),
            parts.len(),
            reading[runs / 2].as_secs_f64() * 1e3,
            finding[runs / 2].as_secs_f64() * 1e3
        );
    }
}
