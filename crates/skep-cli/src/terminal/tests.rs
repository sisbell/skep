use std::collections::VecDeque;

use skep_client::sheet::{KeyFile, Label, Seed};

use super::*;

/// A screen whose answers are scripted, keeping every line said, prompt
/// and text shown, in order — the person gone once the script is.
struct ScriptedScreen {
    answers: VecDeque<String>,
    said: Vec<String>,
}

fn script(answers: &[&str]) -> ScriptedScreen {
    ScriptedScreen { answers: answers.iter().map(|a| a.to_string()).collect(), said: Vec::new() }
}

impl Screen for ScriptedScreen {
    fn answer(&mut self, prompt: &str) -> Result<String, Abandoned> {
        self.said.push(prompt.to_string());
        self.answers.pop_front().ok_or(Abandoned)
    }

    fn talk(&mut self, line: &str) {
        self.said.push(line.to_string());
    }

    fn show(&mut self, text: &str) {
        self.said.push(text.to_string());
    }

    fn clear(&mut self) {
        self.said.push(CLEAR.to_string());
    }
}

fn question(text: &str) -> Question {
    Question { text: text.into() }
}

/// A seed as a person types it off a print — its R42 groups spaced, one
/// in capitals — and the seed as the walk receives it: the spacing gone
/// and nothing else touched.
const TYPED_SEED: &str = "0E0E0E0E 0e0e0e0e 0e0e0e0e 0e0e0e0e  0e0e0e0e 0e0e0e0e 0e0e0e0e\t0e0e0e0e";

fn received_seed() -> String {
    format!("0E0E0E0E{}", "0e0e0e0e".repeat(7))
}

/// What the terminal is handed is INERT (AUTH-5.2): an escape, a carriage
/// return, a bell and a bidi control each shown as its code point, the line
/// breaks kept; the box's rules and its padding pass whole; and a text
/// rendered once passes as it stands, so a label a walk rendered already
/// is never rendered into another spelling.
#[test]
fn every_line_the_terminal_is_handed_is_inert() {
    assert_eq!(inert("a\x1b[2Jb\rc\nd\u{202e}e\x07"), "a<U+001B>[2Jb<U+000D>c\nd<U+202E>e<U+0007>");
    let ruled = boxed(&["the seed".into(), "é—".into()]);
    assert_eq!(inert(&ruled), ruled, "the box passes whole");
    assert_eq!(inert(&inert("\x1b]52;c;cHduZWQ=\x07")), inert("\x1b]52;c;cHduZWQ=\x07"), "rendered twice, the same");
}

/// Every line of the box is padded to the widest, measured in chars: a
/// line holding multi-byte text lines up with one that holds none.
#[test]
fn the_box_is_ruled_to_the_widest_line() {
    let b = boxed(&["ab".into(), "abcd".into(), "é—".into()]);
    let lines: Vec<&str> = b.lines().collect();
    assert_eq!(lines.len(), 5);
    assert!(lines[0].starts_with('┌') && lines[4].starts_with('└'));
    assert!(lines.iter().all(|l| l.chars().count() == lines[0].chars().count()), "{b}");
    assert_eq!(lines[3], format!("│ é—{} │", " ".repeat(18)), "padded to the 20-char floor");
}

/// The import's arm is the person's answer, never a guess from what was
/// typed: a seed, a seed with one character wrong, and a path each name
/// no arm and are asked again.
#[test]
fn the_import_arm_is_the_persons_answer_never_a_guess_from_the_text() {
    assert_eq!(arm("f"), Some(Arm::File));
    assert_eq!(arm(" Print "), Some(Arm::Print));
    assert_eq!(arm("NEITHER"), Some(Arm::Neither));
    let seed = "0e".repeat(32);
    assert_eq!(arm(&seed), None, "a seed typed at the question");
    assert_eq!(arm(&format!("{}O{}", &seed[..10], &seed[11..])), None, "a seed with an O for a 0");
    assert_eq!(arm("/home/me/anchor-a.skep-key"), None, "a path");
}

/// A statement is said with the rule it renders; a question's text is
/// its prompt, and its answer comes back as typed.
#[test]
fn a_statement_is_said_with_its_rule_and_a_question_answered_as_typed() {
    let mut screen = script(&["  http://127.0.0.1:8642 "]);
    moment::say(&mut screen, &Statement { rule: "AUTH-5.42", text: "this name is permanent".into() });
    assert_eq!(moment::ask(&mut screen, &question("the board: ")), Ok("  http://127.0.0.1:8642 ".into()));
    assert_eq!(screen.said, ["[AUTH-5.42] this name is permanent", "the board: "]);
}

/// A name box says its title and statements, offers its default and
/// takes it on an empty answer, and takes a typed name as typed; a box
/// with no default answers the empty name, for the walk's domain test to
/// refuse; the person gone abandons it.
#[test]
fn a_name_box_says_its_statements_and_takes_its_default_on_an_empty_answer() {
    let name_box = |default: Option<&str>| LabelBox { title: "name anchor 1".into(), statements: vec!["it is permanent".into()], default: default.map(Into::into) };
    let mut screen = script(&[""]);
    assert_eq!(moment::label(&mut screen, name_box(Some("host 2026-10-07"))), Ok("host 2026-10-07".into()));
    assert_eq!(screen.said, ["name anchor 1:", "  it is permanent", "name anchor 1 [host 2026-10-07]: "]);
    assert_eq!(moment::label(&mut script(&["paper a"]), name_box(Some("host 2026-10-07"))), Ok("paper a".into()));
    let mut screen = script(&[""]);
    assert_eq!(moment::label(&mut screen, name_box(None)), Ok(String::new()));
    assert_eq!(screen.said[2], "name anchor 1: ", "no default offered");
    assert_eq!(moment::label(&mut script(&[]), name_box(None)), Err(Abandoned));
}

/// A yes or a no, and nothing else: an answer that is neither is asked
/// again, saying why; the person gone abandons it.
#[test]
fn a_yes_no_answer_that_is_neither_is_asked_again() {
    let mut screen = script(&["maybe", " Yes "]);
    assert_eq!(moment::yes_no(&mut screen, &question("do the prints match?")), Ok(true));
    assert_eq!(screen.said, ["do the prints match? [y/n]: ", "answer y or n", "do the prints match? [y/n]: "]);
    assert_eq!(moment::yes_no(&mut script(&["N"]), &question("?")), Ok(false));
    assert_eq!(moment::yes_no(&mut script(&["maybe"]), &question("?")), Err(Abandoned));
}

/// A typed confirmation answers the text typed, trimmed: the row, a
/// wrong row, a `yes` and a `no` each come back as typed, never reduced
/// to a yes or a no (AUTH-5.46); the person gone abandons it.
#[test]
fn a_typed_confirmation_answers_the_text_typed_never_a_yes_or_a_no() {
    let row = Confirmation { text: "retire 0e0e0e0e (phone)?".into(), expected: "0e0e0e0e".into() };
    for typed in ["0e0e0e0e", "0e0e0e0f", "yes", "no"] {
        assert_eq!(moment::confirm_typed(&mut script(&[&format!("  {typed} ")]), &row).as_deref(), Ok(typed));
    }
    let mut screen = script(&["0e0e0e0e"]);
    moment::confirm_typed(&mut screen, &row).unwrap();
    assert_eq!(screen.said, ["retire 0e0e0e0e (phone)?", "type `0e0e0e0e` to confirm, or `no`: "]);
    assert_eq!(moment::confirm_typed(&mut script(&[]), &row), Err(Abandoned));
}

/// The re-type (AUTH-5.41): an empty seed declines it and the prefix is
/// never asked; a typed seed loses its spacing and nothing else, and the
/// prefix is trimmed — the walk judges both; the person gone at the
/// prefix abandons it.
#[test]
fn an_empty_retype_declines_without_asking_the_prefix_and_a_typed_one_loses_its_spacing() {
    let r = Retype { prompt: "type the seed from the print".into() };
    let mut screen = script(&["", "never asked"]);
    assert_eq!(moment::retype(&mut screen, &r), Ok(Retyped::Declined));
    assert_eq!(screen.answers.len(), 1, "the prefix is never asked: {:?}", screen.said);
    let mut screen = script(&[TYPED_SEED, " 0E0E0E0E "]);
    assert_eq!(moment::retype(&mut screen, &r), Ok(Retyped::Typed { seed_hex: received_seed(), fingerprint_prefix: "0E0E0E0E".into() }));
    assert_eq!(screen.said[0], "type the seed from the print");
    assert_eq!(moment::retype(&mut script(&[TYPED_SEED]), &r), Err(Abandoned));
}

/// The import asks which arm the person holds before anything else, and
/// each arm reads its own answers: the FILE's path, asked again on an
/// empty line; the PRINT's seed, its spacing removed, and prefix; and
/// NEITHER, an answer and never an error (§4a.2 R1); the person gone
/// mid-arm abandons it.
#[test]
fn the_import_asks_which_arm_first_and_each_arm_reads_its_own_answers() {
    const ARM: &str = "which do you hold: the kept FILE (f), the PRINT (p), or NEITHER (n)? ";
    let i = Import { prompt: "import one anchor".into() };
    let mut screen = script(&["/media/usb/anchor-a.skep-key", "f", "", " /media/usb/anchor-a.skep-key "]);
    assert_eq!(moment::import(&mut screen, &i), Ok(Imported::File("/media/usb/anchor-a.skep-key".into())));
    assert_eq!(screen.said, ["import one anchor", ARM, "answer f, p or n", ARM, "the file's path: ", "a path is required", "the file's path: "]);
    let mut screen = script(&["p", TYPED_SEED, " 0E0E0E0E "]);
    assert_eq!(moment::import(&mut screen, &i), Ok(Imported::Typed { seed_hex: received_seed(), fingerprint_prefix: "0E0E0E0E".into() }));
    assert_eq!(moment::import(&mut script(&["n"]), &i), Ok(Imported::Neither));
    assert_eq!(moment::import(&mut script(&["f"]), &i), Err(Abandoned));
}

/// Kept or placed (AUTH-5.54 step 3's file arm): an answer that is
/// neither is asked again, naming the path each time; the person gone
/// abandons it.
#[test]
fn kept_or_placed_is_asked_again_until_the_answer_is_one() {
    let h = HandedPath { path: "/media/usb/anchor-a.skep-key".into(), text: "the file you handed in".into() };
    let asked = "is /media/usb/anchor-a.skep-key the KEPT artifact (k) or a PLACED copy (p)? ";
    let mut screen = script(&["yes", "KEPT"]);
    assert_eq!(moment::kept_or_placed(&mut screen, &h), Ok(KeptOrPlaced::Kept));
    assert_eq!(screen.said, ["the file you handed in", asked, "answer k or p", asked]);
    assert_eq!(moment::kept_or_placed(&mut script(&["p"]), &h), Ok(KeptOrPlaced::Placed));
    assert_eq!(moment::kept_or_placed(&mut script(&[]), &h), Err(Abandoned));
}

/// A destination is a directory, asked again on an empty line — no
/// default is offered (§4.2 step 4) — and trimmed; the person gone
/// abandons it.
#[test]
fn a_destination_is_asked_again_on_an_empty_line_and_offers_no_default() {
    let d = Destination { prompt: "where does anchor 1's file go?".into(), which: 0 };
    let mut screen = script(&["", " /media/usb "]);
    assert_eq!(moment::destination(&mut screen, &d), Ok(PathBuf::from("/media/usb")));
    assert_eq!(screen.said, ["where does anchor 1's file go?", "directory: ", "a directory is required; no default is offered", "directory: "]);
    assert_eq!(moment::destination(&mut script(&[]), &d), Err(Abandoned));
}

/// The sheet is a ruled box holding every field the library lists — the
/// seed among them, its two lines of groups under its name — held until
/// the person answers that it is printed; the person gone abandons it.
/// The dismissal clears the screen and its scrollback (§5.2; §4.2 step 6).
#[test]
fn the_sheet_is_shown_boxed_and_held_until_answered_and_the_dismissal_clears_it() {
    let fields = KeyFile::new(Seed::new([0x0e; 32]), true, Some(Label::new("paper a").unwrap()), None).sheet();
    let mut screen = script(&[""]);
    assert_eq!(moment::sheet(&mut screen, &Sheet { fields: fields.clone() }), Ok(()));
    let shown = &screen.said[0];
    assert!(shown.starts_with('┌') && shown.contains("skep anchor sheet — print this; the seed below is the key"), "{shown}");
    for (name, value) in fields.lines() {
        assert!(shown.contains(&name) && value.lines().all(|part| shown.contains(part)), "`{name}` in the box: {shown}");
    }
    let seed_row = format!("{:<12}{}", "seed", "0e0e0e0e ".repeat(4).trim_end());
    assert!(shown.contains(&format!("│ {seed_row}")) && shown.contains(&format!("│ {:<12}{}", "", "0e0e0e0e ".repeat(4).trim_end())), "{shown}");
    assert_eq!(screen.said[1..], ["press return once the sheet is printed: "]);
    assert_eq!(moment::sheet(&mut script(&[]), &Sheet { fields }), Err(Abandoned));
    let mut screen = script(&[]);
    moment::dismiss(&mut screen);
    assert_eq!(screen.said, ["\x1b[2J\x1b[3J\x1b[H"]);
}
