//! The text edit's unit suite: the find, the trim, the text a delivery is
//! read into, spliced and rearranged, the edit against a scripted board
//! (`Script`, the edit's [`Calls`]), and the edit through the shell's rows
//! scripted (`Rowed`, its [`Rows`]) — a death followed to its re-open, the
//! error member, the halts left for the row to say. The scripted boards
//! serve the child suites of `text.edit` and `text.move` too
//! (`edit/tests.rs`, `moving/tests.rs`). The rows themselves, their order
//! and their door, run against the daemon in `shell/tests/text.rs`.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::time::Instant;

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

/// An insert's bytes are found wherever the draft now arranges them.
///
/// Whole and in order they stand at one ordinal, however the board split the
/// run that holds them; arranged nowhere, they are nowhere; and cut, moved
/// apart, placed in part or placed twice they are parted, which no single
/// removal takes back.
#[test]
fn an_inserts_bytes_are_found_wherever_the_draft_now_arranges_them() {
    let image = |runs: Value| json!({"resp": "runs", "as_of": 9, "runs": runs});
    let addr = "1.0.1.0.64.0.1.80";
    let run = |i: &str, width: u64| json!({"i_start": i, "width": width.to_string()});
    assert_eq!(placed(&image(json!([run("1.0.1.0.64.0.1.1", 20), run(addr, 3), run("1.0.1.0.64.0.1.21", 5)])), addr, 3), Some(Placed::Whole(21)));
    assert_eq!(placed(&image(json!([run(addr, 3)])), addr, 3), Some(Placed::Whole(1)));
    assert_eq!(placed(&image(json!([run("1.0.1.0.64.0.1.70", 12), run("1.0.1.0.64.0.1.82", 9)])), addr, 3), Some(Placed::Whole(11)), "one run and the next, I-adjacent: the board split them");
    assert_eq!(placed(&image(json!([run("1.0.1.0.64.0.1.1", 20)])), addr, 3), Some(Placed::Nowhere));
    assert_eq!(placed(&image(json!([])), addr, 3), Some(Placed::Nowhere));
    assert_eq!(placed(&image(json!([run("1.0.1.0.9.0.1.80", 3)])), addr, 3), Some(Placed::Nowhere), "another document's addresses");
    assert_eq!(placed(&image(json!([run(addr, 2)])), addr, 3), Some(Placed::Parted), "one of the three removed");
    assert_eq!(placed(&image(json!([run(addr, 1), run("1.0.1.0.64.0.1.1", 4), run("1.0.1.0.64.0.1.81", 2)])), addr, 3), Some(Placed::Parted), "cut by another's text");
    assert_eq!(placed(&image(json!([run("1.0.1.0.64.0.1.81", 2), run(addr, 1)])), addr, 3), Some(Placed::Parted), "out of order");
    assert_eq!(placed(&image(json!([run(addr, 3), run(addr, 3)])), addr, 3), Some(Placed::Parted), "placed twice");
    for unread in [json!({"resp": "rejected"}), image(json!([{"i_start": "1.0.1.0.64.0.1.x", "width": "3"}])), image(json!([{"i_start": addr}]))] {
        assert_eq!(placed(&unread, addr, 3), None, "{unread}");
    }
    assert_eq!(placed(&image(json!([])), "nonsense", 3), None);
}

// ── the edit, against a scripted board ──────────────────────────────────

/// A board answered from a script: each call's answer in order, each call
/// kept.
pub(super) struct Script {
    answers: RefCell<VecDeque<Result<Value, Refusal>>>,
    pub(super) sent: RefCell<Vec<Value>>,
}

impl Script {
    /// Returns a board that answers its calls with `answers`, in order.
    pub(super) fn of(answers: Vec<Result<Value, Refusal>>) -> Script {
        Script { answers: RefCell::new(answers.into()), sent: RefCell::new(Vec::new()) }
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

/// The image a scripted undo reads: the insert's bytes at `ordinal`.
fn image_with(ordinal: u64, width: u64, as_of: u64) -> Result<Value, Refusal> {
    Ok(
        json!({"resp": "runs", "as_of": as_of, "runs": [{"i_start": "1.0.1.0.64.0.1.1", "width": (ordinal - 1).to_string()}, {"i_start": MINTED, "width": width.to_string()}, {"i_start": format!("1.0.1.0.64.0.1.{ordinal}"), "width": "9"}]}),
    )
}

/// The whole-content image frame an undo reads.
pub(super) fn image_frame() -> Value {
    frames::image(DOC, 1, u64::MAX)
}

/// An edit that only inserts or only removes is one write, typed against
/// the first read.
///
/// The write carries the `as_of` of the read the extent came from, though a
/// later read of the same call answered a later position; the answer names
/// the ordinal, the widths, the address the board minted the new bytes at
/// and the commit (the mutant that types the write against a read made just
/// before it sends that read, and its position).
#[test]
fn an_edit_that_only_inserts_or_only_removes_is_one_write_typed_against_the_first_read() {
    let word = ordinal_of(CODE, "add");
    let (answer, sent) = edit("add(", "addition(", vec![Ok(json!({"resp": "ack_addr", "addr": MINTED, "at": 44}))]);
    assert_eq!(sent, [frames::insert_text(DOC, word + 3, "ition", READ_AT, None)]);
    assert_eq!(
        answer.expect("an answer"),
        Answer { value: json!({"outcome": "replaced", "doc": DOC, "ordinal": (word + 3).to_string(), "removed": "0", "inserted": "5", "addr": MINTED, "at": 44}), is_error: false }
    );
    let (answer, sent) = edit("total = add", "add", vec![Ok(json!({"resp": "ack", "at": 45}))]);
    assert_eq!(sent, [frames::delete(DOC, ordinal_of(CODE, "total"), 8, READ_AT, None)]);
    assert_eq!(
        answer.expect("an answer"),
        Answer { value: json!({"outcome": "replaced", "doc": DOC, "ordinal": ordinal_of(CODE, "total").to_string(), "removed": "8", "inserted": "0", "at": 45}), is_error: false }
    );
}

/// A replacement is two writes, the second typed against the first's commit.
///
/// The new bytes are inserted directly after the old ones, typed against
/// the read; the old ones are then removed, typed against the insert's own
/// commit, so nothing may have changed the draft between the two.
#[test]
fn a_replacement_is_two_writes_the_second_typed_against_the_firsts_commit() {
    let word = ordinal_of(CODE, "add");
    let (answer, sent) = edit("add", "subtract", vec![Ok(json!({"resp": "ack_addr", "addr": MINTED, "at": 44})), Ok(json!({"resp": "ack", "at": 45}))]);
    assert_eq!(sent, [frames::insert_text(DOC, word + 3, "subtract", READ_AT, None), frames::delete(DOC, word, 3, 44, None)]);
    assert_eq!(
        answer.expect("an answer"),
        Answer { value: json!({"outcome": "replaced", "doc": DOC, "ordinal": word.to_string(), "removed": "3", "inserted": "8", "addr": MINTED, "at": 45}), is_error: false }
    );
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

/// A stale first write is dropped, and nothing of the edit stands.
///
/// The board refuses the first write as typed against an older state, and
/// the shell holds it; the edit reads the verdict off its line, drops the
/// line, and answers the verdict as data — for an edit of one write and for
/// the insert of two, whose removal is then never sent.
#[test]
fn a_stale_first_write_is_dropped_and_nothing_of_the_edit_stands() {
    let verdict = moved_verdict("insert", READ_AT, 43);
    let word = ordinal_of(CODE, "add");
    for (new, write) in [("addition", frames::insert_text(DOC, word + 3, "ition", READ_AT, None)), ("subtract", frames::insert_text(DOC, word + 3, "subtract", READ_AT, None))] {
        let (answer, sent) = edit("add", new, vec![held_answer(3, "moved"), lines(3, "moved", verdict.clone()), Ok(json!({}))]);
        assert_eq!(sent, [vec![write], settling(3)].concat(), "the write, then its line read and dropped: no other write");
        assert_eq!(answer.expect("an answer"), Answer { value: json!({"outcome": "refused", "cause": "arrangement_moved", "doc": DOC, "refusal": verdict}), is_error: false });
    }
}

/// A write the board refuses is answered with its verdict, its line dropped.
///
/// A refused run's cause is the board's code, whatever detail its held
/// cause carries beside it, and its verdict rides under `refusal`.
#[test]
fn a_write_the_board_refuses_is_answered_with_its_verdict_and_its_line_dropped() {
    let verdict = json!({"resp": "rejected", "op": "insert", "code": "not_owner", "disposition": "permanent", "site": {"addr": DOC}});
    let (answer, sent) = edit(
        "add",
        "subtract",
        vec![held_answer(2, "not_owner:the session does not own the document"), lines(2, "not_owner:the session does not own the document", verdict.clone()), Ok(json!({"may_have_landed": []}))],
    );
    assert_eq!(sent[1..], settling(2)[..]);
    assert_eq!(answer.expect("an answer"), Answer { value: json!({"outcome": "refused", "cause": "not_owner", "doc": DOC, "refusal": verdict}), is_error: false });
}

/// A write the shell could not get to the board is dropped, and is an error.
///
/// Held for the board — halted, unreachable, behind an earlier line — the
/// write carries no verdict: its line is dropped, so nothing lands later
/// with no one to finish the edit, and the answer is `isError`, the hold's
/// cause its cause. A line the list no longer names is dropped all the same,
/// and a refusal of the list read is no verdict.
#[test]
fn a_write_the_shell_could_not_get_to_the_board_is_dropped_and_is_an_error() {
    for cause in ["halted", "unreachable", "behind", "session_died"] {
        let (answer, sent) = edit("add", "subtract", vec![held_answer(5, cause), lines(5, cause, Value::Null), Ok(json!({}))]);
        assert_eq!(sent[1..], settling(5)[..], "{cause}");
        assert_eq!(answer.expect("an answer"), Answer { value: json!({"outcome": "refused", "cause": cause, "doc": DOC}), is_error: true }, "{cause}");
    }
    let shells_own = json!({"kind": "shell", "name": "session_died", "reason": {"arm": "restart"}});
    let (answer, _) = edit("add", "addition", vec![held_answer(5, "session_died"), lines(5, "session_died", shells_own), Ok(json!({}))]);
    assert_eq!(
        answer.expect("an answer"),
        Answer { value: json!({"outcome": "refused", "cause": "session_died", "doc": DOC}), is_error: true },
        "the shell's own refusal beside a line is no verdict of the board's"
    );
    let (answer, _) = edit("add", "addition", vec![held_answer(5, "halted"), Err(Refusal::shell(Name::STORE_HALTED, json!({"why": "damaged"}))), Ok(json!({}))]);
    assert_eq!(answer.expect("an answer").value, json!({"outcome": "refused", "cause": "halted", "doc": DOC}));
}

/// A drop that finds the write landed is a write that landed.
///
/// A line whose write's answer was lost is read for its landing by the drop:
/// `kept`, or a line the shell's own resend settled first, is a landing with
/// no ack. An edit of one write then landed whole, its commit and address
/// unnamed; a removal that landed completes its replacement; and an insert
/// that landed with no ack leaves the two spans standing, which the answer
/// says, since the removal cannot be typed against a commit no answer named.
#[test]
fn a_drop_that_finds_the_write_landed_is_a_write_that_landed() {
    let word = ordinal_of(CODE, "add");
    let gone = || Err(Refusal::shell(Name::NO_SUCH_HELD, json!({"held": 6})));
    for landed in [Ok(json!({"kept": true})), gone()] {
        let (answer, _) = edit("add", "addition", vec![held_answer(6, "unreachable"), lines(6, "unreachable", Value::Null), landed]);
        assert_eq!(answer.expect("an answer"), Answer { value: json!({"outcome": "replaced", "doc": DOC, "ordinal": (word + 3).to_string(), "removed": "0", "inserted": "5"}), is_error: false });
    }
    let (answer, sent) =
        edit("add", "subtract", vec![Ok(json!({"resp": "ack_addr", "addr": MINTED, "at": 44})), held_answer(6, "unreachable"), lines(6, "unreachable", Value::Null), Ok(json!({"kept": true}))]);
    assert_eq!(sent.len(), 4, "the two writes and the settling: no undo");
    assert_eq!(answer.expect("an answer"), Answer { value: json!({"outcome": "replaced", "doc": DOC, "ordinal": word.to_string(), "removed": "3", "inserted": "8", "addr": MINTED}), is_error: false });
    let (answer, sent) = edit("add", "subtract", vec![held_answer(6, "unreachable"), lines(6, "unreachable", Value::Null), Ok(json!({"kept": true}))]);
    assert_eq!(sent.len(), 3, "the insert and its settling: the removal is not sent");
    let stands =
        json!({"outcome": "partial", "doc": DOC, "new_text": {"ordinal": (word + 3).to_string(), "width": "8"}, "old_text": {"ordinal": word.to_string(), "width": "3"}, "cause": "answer_lost"});
    assert_eq!(answer.expect("an answer"), Answer { value: stands, is_error: true });
}

/// A line the shell will not drop stays held, and the answer names it.
///
/// The shell refuses a drop where it cannot tell whether the write landed,
/// or a send has the line out: the line stands, and the answer is `held`,
/// `isError`, with the line's ordinal, its cause and the write it is — and,
/// for an edit of two writes, the two spans as they stand or may.
#[test]
fn a_line_the_shell_will_not_drop_stays_held_and_the_answer_names_it() {
    let word = ordinal_of(CODE, "add");
    let unread = || Err(Refusal::shell(Name::LANDING_UNREAD, json!({"held": 8, "why": "unanswered"})));
    let out = || Err(Refusal::shell(Name::NOT_RESOLVABLE, json!({"held": 8})));
    for refused in [unread(), out()] {
        let (answer, _) = edit("add", "addition", vec![held_answer(8, "unreachable"), lines(8, "unreachable", Value::Null), refused]);
        assert_eq!(answer.expect("an answer"), Answer { value: json!({"outcome": "held", "doc": DOC, "held": 8, "cause": "unreachable", "write": "insert"}), is_error: true });
    }
    let (answer, _) = edit("total = add", "add", vec![held_answer(8, "poisoned"), lines(8, "poisoned", Value::Null), unread()]);
    assert_eq!(answer.expect("an answer").value, json!({"outcome": "held", "doc": DOC, "held": 8, "cause": "poisoned", "write": "delete"}));
    let spans = |new_text: Value| json!({"new_text": new_text, "old_text": {"ordinal": word.to_string(), "width": "3"}});
    let (answer, sent) = edit("add", "subtract", vec![held_answer(8, "unreachable"), lines(8, "unreachable", Value::Null), unread()]);
    assert_eq!(sent.len(), 3, "the removal is not sent behind an insert that may not have landed");
    let mut expected = json!({"outcome": "held", "doc": DOC, "held": 8, "cause": "unreachable", "write": "insert"});
    expected.as_object_mut().expect("an object").extend(spans(json!({"ordinal": (word + 3).to_string(), "width": "8"})).as_object().expect("an object").clone());
    assert_eq!(answer.expect("an answer"), Answer { value: expected, is_error: true });
    let (answer, sent) = edit("add", "subtract", vec![Ok(json!({"resp": "ack_addr", "addr": MINTED, "at": 44})), held_answer(8, "unreachable"), lines(8, "unreachable", Value::Null), unread()]);
    assert_eq!(sent.len(), 4, "no undo while the removal may have landed");
    let mut expected = json!({"outcome": "held", "doc": DOC, "held": 8, "cause": "unreachable", "write": "delete"});
    expected.as_object_mut().expect("an object").extend(spans(json!({"ordinal": (word + 3).to_string(), "width": "8", "addr": MINTED, "at": 44})).as_object().expect("an object").clone());
    assert_eq!(answer.expect("an answer"), Answer { value: expected, is_error: true });
}

/// A refused second write has the insert taken back by identity.
///
/// The removal is refused as typed against an older state: another writer's
/// change landed between the two commits. The edit drops its line, reads
/// the draft's whole image, finds the bytes its insert minted where that
/// change moved them, and removes them, typed against that read; the answer
/// is the removal's verdict, as data, nothing standing.
#[test]
fn a_refused_second_write_has_the_insert_taken_back_by_identity() {
    let word = ordinal_of(CODE, "add");
    let verdict = moved_verdict("delete", 44, 46);
    let (answer, sent) = edit(
        "add",
        "subtract",
        vec![
            Ok(json!({"resp": "ack_addr", "addr": MINTED, "at": 44})),
            held_answer(4, "moved"),
            lines(4, "moved", verdict.clone()),
            Ok(json!({})),
            image_with(word + 3 + 9, 8, 50),
            Ok(json!({"resp": "ack", "at": 51})),
        ],
    );
    let expected =
        [vec![frames::insert_text(DOC, word + 3, "subtract", READ_AT, None), frames::delete(DOC, word, 3, 44, None)], settling(4), vec![image_frame(), frames::delete(DOC, word + 3 + 9, 8, 50, None)]]
            .concat();
    assert_eq!(sent, expected, "the insert, the removal, its line settled, the image, and the insert's bytes removed where they stand");
    assert_eq!(answer.expect("an answer"), Answer { value: json!({"outcome": "refused", "cause": "arrangement_moved", "doc": DOC, "refusal": verdict}), is_error: false });
    // The insert's bytes arranged nowhere already: nothing to take back.
    let gone = Ok(json!({"resp": "runs", "as_of": 50, "runs": [{"i_start": "1.0.1.0.64.0.1.1", "width": "9"}]}));
    let (answer, sent) = edit("add", "subtract", vec![Ok(json!({"resp": "ack_addr", "addr": MINTED, "at": 44})), held_answer(4, "moved"), lines(4, "moved", verdict.clone()), Ok(json!({})), gone]);
    assert_eq!(sent.len(), 5, "the image read alone");
    assert_eq!(answer.expect("an answer").value["cause"], "arrangement_moved");
    // An undo whose answer was lost and whose landing the drop finds.
    let (answer, _) = edit(
        "add",
        "subtract",
        vec![
            Ok(json!({"resp": "ack_addr", "addr": MINTED, "at": 44})),
            held_answer(4, "moved"),
            lines(4, "moved", verdict.clone()),
            Ok(json!({})),
            image_with(word + 3, 8, 50),
            held_answer(5, "unreachable"),
            lines(5, "unreachable", Value::Null),
            Ok(json!({"kept": true})),
        ],
    );
    assert_eq!(answer.expect("an answer").value["outcome"], "refused");
}

/// An undo refused as stale is made again from a fresh read, three times.
///
/// The draft keeps moving: each removal of the insert's bytes is refused as
/// typed against an older state, its line dropped, and the image read
/// again. After the third the edit stops, and the answer is `partial`,
/// `isError`: the new bytes standing — their ordinal and width, the address
/// and the commit the insert's ack named — the old ones not removed, and
/// the removal's verdict.
#[test]
fn an_undo_refused_as_stale_is_made_again_from_a_fresh_read_three_times() {
    let word = ordinal_of(CODE, "add");
    let verdict = moved_verdict("delete", 44, 46);
    let mut script = vec![Ok(json!({"resp": "ack_addr", "addr": MINTED, "at": 44})), held_answer(4, "moved"), lines(4, "moved", verdict.clone()), Ok(json!({}))];
    let mut expected = [vec![frames::insert_text(DOC, word + 3, "subtract", READ_AT, None), frames::delete(DOC, word, 3, 44, None)], settling(4)].concat();
    for attempt in 0..UNDO_TRIES as u64 {
        let (ordinal, as_of, line) = (word + 3 + attempt + 1, 50 + attempt, 5 + attempt);
        script.extend([image_with(ordinal, 8, as_of), held_answer(line, "moved"), lines(line, "moved", moved_verdict("delete", as_of, as_of + 1)), Ok(json!({}))]);
        expected.extend([vec![image_frame(), frames::delete(DOC, ordinal, 8, as_of, None)], settling(line)].concat());
    }
    let (answer, sent) = edit("add", "subtract", script);
    assert_eq!(sent, expected, "three undos, each typed against its own read");
    let stands = json!({
        "outcome": "partial", "doc": DOC,
        "new_text": {"ordinal": (word + 3).to_string(), "width": "8", "addr": MINTED, "at": 44},
        "old_text": {"ordinal": word.to_string(), "width": "3"},
        "cause": "arrangement_moved", "refusal": verdict,
    });
    assert_eq!(answer.expect("an answer"), Answer { value: stands, is_error: true });
}

/// An undo that cannot be made leaves the answer partial.
///
/// The image refused, the insert's bytes parted by another's change, or the
/// undo's write refused for any cause but a moved draft — its line dropped,
/// or none held: each stops the undo at once, and the answer says what
/// stands, no line of the edit's held. Where the removal was held for the
/// board, the partial's cause is the hold's and it carries no verdict.
#[test]
fn an_undo_that_cannot_be_made_leaves_the_answer_partial() {
    let word = ordinal_of(CODE, "add");
    let verdict = moved_verdict("delete", 44, 46);
    let opening = || vec![Ok(json!({"resp": "ack_addr", "addr": MINTED, "at": 44})), held_answer(4, "moved"), lines(4, "moved", verdict.clone()), Ok(json!({}))];
    let too_large =
        || Err(Refusal::Board(Refused { status: 200, code: "image_too_large".into(), detail: None, op: Some("image".into()), body: json!({"resp": "rejected", "code": "image_too_large"}) }));
    let parted = Ok(json!({"resp": "runs", "as_of": 50, "runs": [{"i_start": MINTED, "width": "4"}, {"i_start": "1.0.1.0.64.0.1.1", "width": "2"}, {"i_start": "1.0.1.0.64.0.1.84", "width": "4"}]}));
    let refused_run = json!({"resp": "rejected", "op": "delete", "code": "not_arranged", "disposition": "permanent"});
    for undo in [
        vec![too_large()],
        vec![parted],
        vec![image_with(word + 4, 8, 50), held_answer(5, "not_arranged"), lines(5, "not_arranged", refused_run), Ok(json!({}))],
        vec![image_with(word + 4, 8, 50), Err(Refusal::shell(Name::ANOTHER_WINDOW, json!({"op": "delete"})))],
    ] {
        let (answer, _) = edit("add", "subtract", opening().into_iter().chain(undo).collect());
        let answer = answer.expect("an answer");
        assert!(answer.is_error, "{}", answer.value);
        assert_eq!(
            (&answer.value["outcome"], &answer.value["cause"], &answer.value["refusal"], &answer.value["new_text"]["addr"]),
            (&json!("partial"), &json!("arrangement_moved"), &verdict, &json!(MINTED)),
            "{}",
            answer.value
        );
    }
    let (answer, _) = edit("add", "subtract", vec![Ok(json!({"resp": "ack_addr", "addr": MINTED, "at": 44})), held_answer(4, "halted"), lines(4, "halted", Value::Null), Ok(json!({})), too_large()]);
    let answer = answer.expect("an answer");
    assert_eq!((answer.is_error, &answer.value["outcome"], &answer.value["cause"], &answer.value["refusal"]), (true, &json!("partial"), &json!("halted"), &Value::Null), "{}", answer.value);
}

/// A second write the shell refuses outright is undone, or told as partial.
///
/// The removal is refused with no line held — another shell took the
/// board's held store between the two writes. Where the undo lands, the
/// refusal is the call's own, nothing standing; where it does not, the
/// answer is `partial`, the refusal's name its cause and its value beside
/// it.
#[test]
fn a_second_write_the_shell_refuses_outright_is_undone_or_told_as_partial() {
    let word = ordinal_of(CODE, "add");
    let refusal = || Refusal::shell(Name::ANOTHER_WINDOW, json!({"op": "delete"}));
    let (outcome, sent) = edit("add", "subtract", vec![Ok(json!({"resp": "ack_addr", "addr": MINTED, "at": 44})), Err(refusal()), image_with(word + 3, 8, 50), Ok(json!({"resp": "ack", "at": 51}))]);
    assert_eq!(sent[2..], [image_frame(), frames::delete(DOC, word + 3, 8, 50, None)]);
    assert_eq!(outcome.expect_err("the refusal").to_value(), refusal().to_value());
    let (outcome, _) = edit("add", "subtract", vec![Ok(json!({"resp": "ack_addr", "addr": MINTED, "at": 44})), Err(refusal()), Err(refusal())]);
    let answer = outcome.expect("an answer");
    assert_eq!(
        (answer.is_error, &answer.value["outcome"], &answer.value["cause"], &answer.value["refusal"]),
        (true, &json!("partial"), &json!("another_window"), &refusal().to_value()),
        "{}",
        answer.value
    );
    // An insert's ack that names no address and no commit cannot be undone
    // by identity, nor its removal typed: the two spans stand, and are told.
    let (outcome, sent) = edit("add", "subtract", vec![Ok(json!({"resp": "ack"}))]);
    assert_eq!(sent.len(), 1);
    assert_eq!(
        outcome.expect("an answer").value,
        json!({"outcome": "partial", "doc": DOC, "new_text": {"ordinal": (word + 3).to_string(), "width": "8"}, "old_text": {"ordinal": word.to_string(), "width": "3"}, "cause": "unread", "op": "insert"})
    );
}

/// An undo whose line the shell will not drop is answered `held`, naming it.
///
/// The removal does not land — its line dropped with the board's verdict,
/// or refused outright with none held — and the undo's own removal of the
/// new bytes is held: where the shell refuses its drop — it cannot tell
/// whether the removal landed, or a send has the line out — the line stands
/// and may yet remove the new bytes while the old ones stand. The answer is
/// `held`, an error, naming that line, `write` `undo`, both spans beside
/// it (SP-8), and no write follows the line. A death at the undo's dial
/// that no re-open follows refuses the line's drop too, and is answered so;
/// where the restart arm re-opened a session that stands, the line is
/// dropped under it and the answer is `partial`, no line held (the mutants
/// that fold a standing line into `partial`, and that try the undo again
/// behind it).
#[test]
fn an_undo_whose_line_the_shell_will_not_drop_is_answered_held_naming_it() {
    let word = ordinal_of(CODE, "add");
    let ack = || Ok(json!({"resp": "ack_addr", "addr": MINTED, "at": 44}));
    let verdict = moved_verdict("delete", 44, 46);
    let dropped = || vec![ack(), held_answer(4, "moved"), lines(4, "moved", verdict.clone()), Ok(json!({}))];
    let outright = || vec![ack(), Err(Refusal::shell(Name::ANOTHER_WINDOW, json!({"op": "delete"})))];
    let undo = |cause: &str, refused: Result<Value, Refusal>| vec![image_with(word + 4, 8, 50), held_answer(5, cause), lines(5, cause, Value::Null), refused];
    let named = |cause: &str| Answer {
        value: json!({
            "outcome": "held", "doc": DOC, "held": 5, "cause": cause, "write": "undo",
            "new_text": {"ordinal": (word + 3).to_string(), "width": "8", "addr": MINTED, "at": 44},
            "old_text": {"ordinal": word.to_string(), "width": "3"},
        }),
        is_error: true,
    };
    let unread = || Err(Refusal::shell(Name::LANDING_UNREAD, json!({"held": 5, "why": "unanswered"})));
    let out = || Err(Refusal::shell(Name::NOT_RESOLVABLE, json!({"held": 5})));
    for (opening, before) in [(dropped(), 4), (outright(), 2)] {
        for refused in [unread(), out()] {
            let (answer, sent) = edit("add", "subtract", [opening.clone(), undo("unreachable", refused)].concat());
            let answer = answer.expect("an answer");
            assert_eq!(answer, named("unreachable"), "the undo's line, named");
            crate::shapes::assert_declared("TextHeld", &answer.into_value());
            assert_eq!(sent[before..], [vec![image_frame(), frames::delete(DOC, word + 4, 8, 50, None)], settling(5)].concat()[..], "the undo's removal and its line settled: no write after it");
        }
    }
    let asked = Asked { doc: DOC, old: "add", new: "subtract" };
    let rows = Rowed::of([reads_of(CODE), dropped(), vec![image_with(word + 4, 8, 50), held_answer(5, "session_died"), died(None), died(None)]].concat(), vec![]);
    assert_eq!(replace(&Under::new(&rows, "s-1"), asked), Ok(named("session_died")));
    assert_eq!(rows.sessions().len(), 11, "the reads, the two writes, the removal's list and drop, the image, the undo, its list and its drop, each once");
    let reopened = vec![image_with(word + 4, 8, 50), held_answer(5, "session_died"), died(Some("s-2")), lines(5, "session_died", Value::Null), Ok(json!({}))];
    let rows = Rowed::of([reads_of(CODE), dropped(), reopened].concat(), vec!["s-2"]);
    let answer = replace(&Under::new(&rows, "s-1"), asked).expect("an answer");
    assert_eq!((answer.is_error, &answer.value["outcome"], &answer.value["cause"], &answer.value["refusal"]), (true, &json!("partial"), &json!("arrangement_moved"), &verdict), "{}", answer.value);
    assert_eq!(rows.sessions()[9..], ["s-1", "s-2", "s-2"], "the undo's list made again under the re-open, its drop under it");
    let write = crate::shapes::shape("TextHeld").and_then(|shape| shape.fields.iter().find(|field| field.name == "write")).map(|field| field.ty);
    assert_eq!(write, Some("'insert' | 'delete' | 'undo'"), "the shapes declare every write a held line of the edit's may be");
}

/// A refusal of a read is the call's refusal, and a refused first write's.
#[test]
fn a_refusal_of_a_read_or_of_the_first_write_is_the_calls_refusal() {
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
    let (outcome, sent) = edit("add", "subtract", vec![Err(Refusal::shell(Name::ANOTHER_WINDOW, json!({"op": "insert"})))]);
    assert_eq!((outcome.expect_err("the write's refusal").name(), sent.len()), ("another_window", 1), "nothing written, nothing to undo");
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
        assert!(script.sent_past(0).iter().all(|call| !["insert", "delete"].contains(&call["op"].as_str().unwrap_or_default())), "no write");
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
    let script = Script::of([vec![draft(), extent(text.len() as u64)], parts(), vec![Ok(json!({"resp": "ack_addr", "addr": MINTED, "at": 60})), Ok(json!({"resp": "ack", "at": 61}))]].concat());
    let answer = replace_text(&script, &json!({"doc": DOC, "old": "let word", "new": "let name"})).expect("an answer");
    let word = ordinal_of(&text, "word");
    assert_eq!(answer.value, json!({"outcome": "replaced", "doc": DOC, "ordinal": word.to_string(), "removed": "4", "inserted": "4", "addr": MINTED, "at": 61}));
    let rest = text.len() as u64 - READ_POSITIONS;
    assert_eq!(
        script.sent_past(2),
        [
            frames::retrieve_v(DOC, 1, READ_POSITIONS),
            frames::retrieve_v(DOC, READ_POSITIONS + 1, rest),
            frames::insert_text(DOC, word + 4, "name", READ_AT, None),
            frames::delete(DOC, word, 4, 60, None)
        ]
    );
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
    let ack = || Ok(json!({"resp": "ack_addr", "addr": MINTED, "at": 44}));
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

/// A line held at its session's death is dropped under the re-open, or
/// named where no re-open stands.
///
/// The insert's dial met the death, and the shell held it `session_died`:
/// where the restart arm re-opened a session that stands, the line's list
/// and its drop are made again under it, the line dropped, and the edit
/// answers `refused` with nothing standing and nothing held — an error, the
/// write never having reached the board; where none stands, the drop is
/// refused too, the line stands, and the edit answers `held` naming it (the
/// mutant that follows no death leaves the line of a restart held, and the
/// burst lands after an edit that answered nothing of it).
#[test]
fn a_line_held_at_its_sessions_death_is_dropped_under_the_re_open_or_named_where_none_stands() {
    let rows = Rowed::of([reads_of(CODE), vec![held_answer(5, "session_died"), died(Some("s-2")), lines(5, "session_died", Value::Null), Ok(json!({}))]].concat(), vec!["s-2"]);
    assert_eq!(through(&rows), Ok(Answer { value: json!({"outcome": "refused", "cause": "session_died", "doc": DOC}), is_error: true }));
    assert_eq!(rows.named.borrow().iter().skip(3).map(|(row, _)| *row).collect::<Vec<_>>(), [Row::Op, Row::Held, Row::Held, Row::Resolve]);
    assert_eq!(rows.sessions(), ["s-1", "s-1", "s-1", "s-1", "s-1", "s-2", "s-2"], "the list made again under the re-open, the drop under it");
    let rows = Rowed::of([reads_of(CODE), vec![held_answer(5, "session_died"), died(None), died(None)]].concat(), vec![]);
    assert_eq!(through(&rows), Ok(Answer { value: json!({"outcome": "held", "doc": DOC, "held": 5, "cause": "session_died", "write": "insert"}), is_error: true }));
    assert_eq!(rows.sessions().len(), 6, "the reads, the insert, the list and the drop, each once");
}

/// An error answer carries the error member, and a data answer none.
///
/// The row's answer is the edit's object, `error: true` set in it exactly
/// where the edit's answer is an error — a write the shell could not get to
/// the board, a read it does not read, a held line, a partial landing — and
/// nothing beside it in every other (the mutants that set the member on
/// every answer, on none, or as another value).
#[test]
fn an_error_answer_carries_the_error_member_and_a_data_answer_none() {
    let data = json!({"outcome": "refused", "cause": "not_found", "doc": DOC, "count": 0, "as_of": READ_AT});
    assert_eq!(Answer::data(data.clone()).into_value(), data, "data stands as the edit built it");
    let (answer, _) = edit("add", "addition", vec![held_answer(5, "unreachable"), lines(5, "unreachable", Value::Null), Ok(json!({}))]);
    assert_eq!(answer.expect("an answer").into_value(), json!({"outcome": "refused", "cause": "unreachable", "doc": DOC, "error": true}));
    let (answer, _) = edit("add", "addition", vec![held_answer(8, "unreachable"), lines(8, "unreachable", Value::Null), Err(Refusal::shell(Name::LANDING_UNREAD, json!({"held": 8})))]);
    assert_eq!(answer.expect("an answer").into_value(), json!({"outcome": "held", "doc": DOC, "held": 8, "cause": "unreachable", "write": "insert", "error": true}));
    let (answer, _) = edit("add", "addition", vec![Ok(json!({"resp": "ack_addr", "addr": MINTED, "at": 44}))]);
    assert_eq!(answer.expect("an answer").into_value().get(ERROR), None, "a landing is data");
}

/// A halt naming a file the edit met and is not answered with is the row's
/// to say.
///
/// The undo's read of the image meets a halt about a file: the edit answers
/// `partial`, and the halt is left for the row to say on `Talk`, once,
/// however often the edit met it; a halt the edit is answered with is
/// `Shell::call`'s to say, and the row leaves it; and a halt naming no file
/// is no one's to say (the mutants that keep no halt, keep the one the call
/// answers too, or keep one twice).
#[test]
fn a_halt_naming_a_file_the_edit_met_and_is_not_answered_with_is_the_rows_to_say() {
    let face = |path: Option<&str>| skep_client::halt::Face { state: "the key file does not read".into(), cause: "c".into(), act: "a".into(), path: path.map(Into::into) };
    let about_a_file = || Err(Refusal::named(Name::STORE_UNREADABLE, face(Some("/store/keys/k"))));
    let verdict = moved_verdict("delete", 44, 46);
    let undone = vec![Ok(json!({"resp": "ack_addr", "addr": MINTED, "at": 44})), held_answer(4, "moved"), lines(4, "moved", verdict), Ok(json!({})), about_a_file()];
    let rows = Rowed::of([reads_of(CODE), undone].concat(), vec![]);
    let under = Under::new(&rows, "s-1");
    let answered = replace(&under, Asked { doc: DOC, old: "add", new: "subtract" });
    assert_eq!(answered.as_ref().map(|answer| answer.value["outcome"].clone()), Ok(json!("partial")));
    assert_eq!(under.unsaid(&answered), [about_a_file().unwrap_err()], "the halt the undo met");
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
