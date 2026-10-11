//! THE DEV ARM (`client.md` §4b.3, §4b.5): where the SECRET and CONSENT
//! moments of a ceremony go in the dev provider — the sheet, the re-type,
//! an anchor's destination, the import, kept-or-placed, every typed
//! confirmation — since "the page never sees a seed" and a consent "is
//! answered in the SHELL's OWN WINDOW and never by the page", and the
//! provider has no window. Two arms: a SCRIPT read from a file, one answer
//! per line in order (the precedent is `skep-client`'s `person::scripted`,
//! a suite's hands), or the AUTO arm, which answers each moment the way a
//! developer on a throwaway board would — the confirmation typed, the
//! anchor files placed under the provider's own directory, the re-type
//! declined, no artifact held. Every answer is SAID on the TALK stream,
//! naming the moment and what was done and never the seed: the sheet a
//! walk shows is kept in this process so a script's `retype sheet` can type
//! it back, and leaves the process nowhere.
//!
//! THE SCRIPT's GRAMMAR, one answer per line, `#` opening a comment:
//!
//! ```text
//! confirm yes | confirm no          a typed confirmation: the row, or `no`
//! typed <text>                      a typed confirmation answered in text
//! retype sheet [n] | wrong | declined   the re-type: off the n-th sheet shown
//!                                   (0 where absent), a wrong hex, declined
//! destination <path>                one anchor file's directory
//! import file <path> | sheet [n] | typed <hex> <prefix> | neither
//! kept | placed                     the kept-or-placed answer
//! abandon                           the person leaves at this moment
//! ```
//!
//! A moment the script has no line for, or a line of another moment's
//! kind, ABANDONS the walk — said so, never a panic: the provider serves
//! on.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use skep_client::person::{Imported, KeptOrPlaced, Retyped};
use skep_client::sheet::SheetFields;

/// Where the shell's TALK lines go: the verb's stderr, a suite's vector.
pub type Talk = Arc<dyn Fn(&str) + Send + Sync>;

/// One scripted answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    Confirm(bool),
    Typed(String),
    RetypeSheet(usize),
    RetypeWrong,
    RetypeDeclined,
    Destination(PathBuf),
    ImportFile(PathBuf),
    ImportSheet(usize),
    ImportTyped { seed_hex: String, fingerprint_prefix: String },
    ImportNeither,
    Kept,
    Placed,
    Abandon,
}

/// A script line the grammar refuses: its number and the line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptError {
    pub line: usize,
    pub text: String,
}

impl std::fmt::Display for ScriptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "script line {}: `{}` is no answer the grammar knows", self.line, self.text)
    }
}

impl std::error::Error for ScriptError {}

/// The script's text parsed, in order.
pub fn parse(text: &str) -> Result<Vec<Answer>, ScriptError> {
    let mut out = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let refused = || ScriptError { line: i + 1, text: line.to_string() };
        let words: Vec<&str> = line.split_whitespace().collect();
        let index = |w: Option<&&str>| -> Result<usize, ScriptError> {
            match w {
                None => Ok(0),
                Some(n) => n.parse().map_err(|_| refused()),
            }
        };
        let answer = match words.as_slice() {
            ["confirm", "yes"] => Answer::Confirm(true),
            ["confirm", "no"] => Answer::Confirm(false),
            ["typed", rest @ ..] if !rest.is_empty() => Answer::Typed(rest.join(" ")),
            ["retype", "sheet", rest @ ..] if rest.len() <= 1 => Answer::RetypeSheet(index(rest.first())?),
            ["retype", "wrong"] => Answer::RetypeWrong,
            ["retype", "declined"] => Answer::RetypeDeclined,
            ["destination", path] => Answer::Destination(PathBuf::from(path)),
            ["import", "file", path] => Answer::ImportFile(PathBuf::from(path)),
            ["import", "sheet", rest @ ..] if rest.len() <= 1 => Answer::ImportSheet(index(rest.first())?),
            ["import", "typed", seed_hex, prefix] => Answer::ImportTyped { seed_hex: (*seed_hex).to_string(), fingerprint_prefix: (*prefix).to_string() },
            ["import", "neither"] => Answer::ImportNeither,
            ["kept"] => Answer::Kept,
            ["placed"] => Answer::Placed,
            ["abandon"] => Answer::Abandon,
            _ => return Err(refused()),
        };
        out.push(answer);
    }
    Ok(out)
}

/// The arm's kind: the auto-answer, or a script.
#[derive(Debug)]
enum Kind {
    /// The auto arm, the anchor files' directory.
    Auto { anchors: PathBuf },
    /// The script's answers, taken in order.
    Script(Mutex<VecDeque<Answer>>),
}

/// THE DEV ARM: the kind, the sheets shown so far (kept here, never sent
/// anywhere), and the TALK sink every answer is said on.
pub struct DevArm {
    kind: Kind,
    sheets: Mutex<Vec<SheetFields>>,
    talk: Talk,
}

impl std::fmt::Debug for DevArm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DevArm({})", match &self.kind { Kind::Auto { .. } => "auto", Kind::Script(_) => "script" })
    }
}

/// What a SECRET or CONSENT moment got: an answer of the moment's own kind,
/// or the person leaving.
#[derive(Debug)]
pub enum Got<T> {
    Answer(T),
    Abandoned,
}

impl DevArm {
    /// The AUTO arm: anchor files under `anchors`, every answer said on
    /// `talk`.
    pub fn auto(anchors: PathBuf, talk: Talk) -> DevArm {
        DevArm { kind: Kind::Auto { anchors }, sheets: Mutex::new(Vec::new()), talk }
    }

    /// The SCRIPT arm over `answers`, every answer said on `talk`.
    pub fn script(answers: Vec<Answer>, talk: Talk) -> DevArm {
        DevArm { kind: Kind::Script(Mutex::new(answers.into())), sheets: Mutex::new(Vec::new()), talk }
    }

    /// Whether this is the script arm.
    pub fn is_script(&self) -> bool {
        matches!(self.kind, Kind::Script(_))
    }

    fn say(&self, line: String) {
        (self.talk)(&format!("dev arm: {line}"));
    }

    /// The script's next answer, or `None` on the auto arm; `Abandon` and
    /// an exhausted script answer the abandonment.
    fn next(&self, moment: &str) -> Option<Got<Answer>> {
        match &self.kind {
            Kind::Auto { .. } => None,
            Kind::Script(answers) => match answers.lock().expect("the script's lock").pop_front() {
                None => {
                    self.say(format!("{moment}: the script has no answer left — the walk is abandoned"));
                    Some(Got::Abandoned)
                }
                Some(Answer::Abandon) => {
                    self.say(format!("{moment}: the script says abandon"));
                    Some(Got::Abandoned)
                }
                Some(a) => Some(Got::Answer(a)),
            },
        }
    }

    /// A script answer of another moment's kind: said, and the walk
    /// abandoned.
    fn wrong_kind(&self, moment: &str, got: &Answer) -> Got<Answer> {
        self.say(format!("{moment}: the script's next answer {got:?} is of another moment's kind — the walk is abandoned"));
        Got::Abandoned
    }

    /// THE SHEET (SECRET): kept here for a `retype sheet`, shown to no one.
    pub fn sheet(&self, fields: SheetFields) {
        self.say(format!("the sheet for fingerprint {} was shown to no one and kept for a scripted re-type", fields.fingerprint_grouped));
        self.sheets.lock().expect("the sheets' lock").push(fields);
    }

    /// THE DISMISSAL (SECRET): nothing was displayed, nothing to clear.
    pub fn dismiss(&self) {
        self.say("the sheet is dismissed (nothing was displayed)".to_string());
    }

    fn off_sheet(&self, n: usize) -> Option<(String, String)> {
        let sheets = self.sheets.lock().expect("the sheets' lock");
        let sheet = sheets.get(n)?;
        Some((sheet.seed_grouped.split_whitespace().collect(), sheet.fingerprint_hex[..8].to_string()))
    }

    /// THE RE-TYPE (SECRET): the auto arm declines it; a script types it off
    /// a sheet shown, types it wrong, or declines.
    pub fn retype(&self) -> Got<Retyped> {
        match self.next("the re-type") {
            None => {
                self.say("the re-type is declined (the auto arm types no seed)".to_string());
                Got::Answer(Retyped::Declined)
            }
            Some(Got::Abandoned) => Got::Abandoned,
            Some(Got::Answer(a)) => match a {
                Answer::RetypeSheet(n) => match self.off_sheet(n) {
                    Some((seed_hex, fingerprint_prefix)) => {
                        self.say(format!("the re-type is typed off sheet {n}"));
                        Got::Answer(Retyped::Typed { seed_hex, fingerprint_prefix })
                    }
                    None => {
                        self.say(format!("the re-type names sheet {n}, which was never shown — the walk is abandoned"));
                        Got::Abandoned
                    }
                },
                Answer::RetypeWrong => {
                    self.say("the re-type is typed wrong, on purpose".to_string());
                    Got::Answer(Retyped::Typed { seed_hex: "00".repeat(32), fingerprint_prefix: "00000000".into() })
                }
                Answer::RetypeDeclined => {
                    self.say("the re-type is declined".to_string());
                    Got::Answer(Retyped::Declined)
                }
                other => match self.wrong_kind("the re-type", &other) {
                    Got::Abandoned => Got::Abandoned,
                    Got::Answer(_) => unreachable!("wrong_kind answers the abandonment"),
                },
            },
        }
    }

    /// ONE ANCHOR FILE's DESTINATION (SECRET): the auto arm places anchor
    /// `which` under its own directory; a script names a path.
    pub fn destination(&self, which: usize) -> Got<PathBuf> {
        match self.next("the destination") {
            None => {
                let Kind::Auto { anchors } = &self.kind else { unreachable!("the auto arm answers no script") };
                let dir = anchors.join(format!("anchor-{which}"));
                self.say(format!("anchor {which} is placed under {}", dir.display()));
                Got::Answer(dir)
            }
            Some(Got::Abandoned) => Got::Abandoned,
            Some(Got::Answer(Answer::Destination(p))) => {
                self.say(format!("anchor {which} is placed under {}", p.display()));
                Got::Answer(p)
            }
            Some(Got::Answer(other)) => match self.wrong_kind("the destination", &other) {
                Got::Abandoned => Got::Abandoned,
                Got::Answer(_) => unreachable!("wrong_kind answers the abandonment"),
            },
        }
    }

    /// A TYPED CONFIRMATION (CONSENT): the auto arm types the row asked
    /// for; a script types the row, `no`, or its own text.
    pub fn confirm(&self, text: &str, expected: &str) -> Got<String> {
        match self.next("the confirmation") {
            None => {
                self.say(format!("the confirmation `{text}` is typed as asked ({expected})"));
                Got::Answer(expected.to_string())
            }
            Some(Got::Abandoned) => Got::Abandoned,
            Some(Got::Answer(a)) => match a {
                Answer::Confirm(true) => {
                    self.say(format!("the confirmation `{text}` is typed as asked ({expected})"));
                    Got::Answer(expected.to_string())
                }
                Answer::Confirm(false) => {
                    self.say(format!("the confirmation `{text}` is answered no"));
                    Got::Answer("no".to_string())
                }
                Answer::Typed(t) => {
                    self.say(format!("the confirmation `{text}` is answered `{t}`"));
                    Got::Answer(t)
                }
                other => match self.wrong_kind("the confirmation", &other) {
                    Got::Abandoned => Got::Abandoned,
                    Got::Answer(_) => unreachable!("wrong_kind answers the abandonment"),
                },
            },
        }
    }

    /// THE ANCHOR IMPORT (SECRET): the auto arm holds neither; a script
    /// hands a file, types off a sheet, types its own, or holds neither.
    pub fn import(&self) -> Got<Imported> {
        match self.next("the import") {
            None => {
                self.say("the import answers neither (the auto arm holds no artifact)".to_string());
                Got::Answer(Imported::Neither)
            }
            Some(Got::Abandoned) => Got::Abandoned,
            Some(Got::Answer(a)) => match a {
                Answer::ImportFile(p) => {
                    self.say(format!("the import hands the file {}", p.display()));
                    Got::Answer(Imported::File(p))
                }
                Answer::ImportSheet(n) => match self.off_sheet(n) {
                    Some((seed_hex, fingerprint_prefix)) => {
                        self.say(format!("the import is typed off sheet {n}"));
                        Got::Answer(Imported::Typed { seed_hex, fingerprint_prefix })
                    }
                    None => {
                        self.say(format!("the import names sheet {n}, which was never shown — the walk is abandoned"));
                        Got::Abandoned
                    }
                },
                Answer::ImportTyped { seed_hex, fingerprint_prefix } => {
                    self.say("the import is typed from the script".to_string());
                    Got::Answer(Imported::Typed { seed_hex, fingerprint_prefix })
                }
                Answer::ImportNeither => {
                    self.say("the import answers neither".to_string());
                    Got::Answer(Imported::Neither)
                }
                other => match self.wrong_kind("the import", &other) {
                    Got::Abandoned => Got::Abandoned,
                    Got::Answer(_) => unreachable!("wrong_kind answers the abandonment"),
                },
            },
        }
    }

    /// KEPT OR PLACED (SECRET): the auto arm answers kept; a script says.
    pub fn kept_or_placed(&self, path: &std::path::Path) -> Got<KeptOrPlaced> {
        match self.next("kept-or-placed") {
            None => {
                self.say(format!("{} is answered kept", path.display()));
                Got::Answer(KeptOrPlaced::Kept)
            }
            Some(Got::Abandoned) => Got::Abandoned,
            Some(Got::Answer(Answer::Kept)) => {
                self.say(format!("{} is answered kept", path.display()));
                Got::Answer(KeptOrPlaced::Kept)
            }
            Some(Got::Answer(Answer::Placed)) => {
                self.say(format!("{} is answered placed", path.display()));
                Got::Answer(KeptOrPlaced::Placed)
            }
            Some(Got::Answer(other)) => match self.wrong_kind("kept-or-placed", &other) {
                Got::Abandoned => Got::Abandoned,
                Got::Answer(_) => unreachable!("wrong_kind answers the abandonment"),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    fn talk() -> (Talk, Arc<Mutex<Vec<String>>>) {
        let lines = Arc::new(Mutex::new(Vec::new()));
        let kept = Arc::clone(&lines);
        (Arc::new(move |l: &str| kept.lock().unwrap().push(l.to_string())), lines)
    }

    /// The grammar: every form parses, a comment and a blank line are
    /// skipped, and a line of no form is refused by number.
    #[test]
    fn the_script_grammar_parses_every_form_and_refuses_the_rest() {
        let text = "# a comment\n\nconfirm yes\nconfirm no\ntyped a wrong row\nretype sheet\nretype sheet 1\nretype wrong\nretype declined\ndestination /tmp/a\nimport file /tmp/k\nimport sheet\nimport typed 00ff abcd\nimport neither\nkept\nplaced\nabandon\n";
        let answers = parse(text).unwrap();
        assert_eq!(answers.len(), 15);
        assert_eq!(answers[2], Answer::Typed("a wrong row".into()));
        assert_eq!(answers[4], Answer::RetypeSheet(1));
        assert_eq!(answers[10], Answer::ImportTyped { seed_hex: "00ff".into(), fingerprint_prefix: "abcd".into() });
        let e = parse("confirm yes\nconfirm maybe\n").unwrap_err();
        assert_eq!((e.line, e.text.as_str()), (2, "confirm maybe"));
        assert!(e.to_string().contains("line 2"));
    }

    /// The auto arm answers each SECRET and CONSENT moment as a developer
    /// would and says so; the seed never reaches the TALK stream.
    #[test]
    fn the_auto_arm_answers_and_says_what_it_did_without_the_seed() {
        let (talk, lines) = talk();
        let arm = DevArm::auto(PathBuf::from("/tmp/anchors"), talk);
        let fields = SheetFields { anchor: true, alg: "mldsa65-ed25519".into(), label: None, fingerprint_hex: "ab".repeat(32), fingerprint_grouped: "abab abab".into(), seed_grouped: "5e5e 5e5e".into(), account: None, principal: None, origin: None };
        arm.sheet(fields);
        assert!(matches!(arm.retype(), Got::Answer(Retyped::Declined)));
        assert!(matches!(arm.destination(1), Got::Answer(p) if p == PathBuf::from("/tmp/anchors/anchor-1")));
        assert!(matches!(arm.confirm("retire?", "abcd efgh"), Got::Answer(row) if row == "abcd efgh"));
        assert!(matches!(arm.import(), Got::Answer(Imported::Neither)));
        assert!(matches!(arm.kept_or_placed(std::path::Path::new("/tmp/k")), Got::Answer(KeptOrPlaced::Kept)));
        arm.dismiss();
        let said = lines.lock().unwrap().join("\n");
        assert!(said.contains("dev arm: the sheet for fingerprint abab abab"), "{said}");
        assert!(!said.contains("5e5e"), "the seed never reaches TALK: {said}");
        assert!(said.contains("anchor 1 is placed under /tmp/anchors/anchor-1"), "{said}");
        assert!(!arm.is_script());
    }

    /// The script arm answers in order, types a re-type off the sheet
    /// shown, and abandons on a wrong kind, on `abandon`, and when
    /// exhausted — never a panic.
    #[test]
    fn the_script_arm_answers_in_order_and_abandons_on_a_wrong_kind_or_exhaustion() {
        let (talk, lines) = talk();
        let arm = DevArm::script(vec![Answer::Confirm(false), Answer::RetypeSheet(0), Answer::Kept, Answer::Abandon], talk);
        assert!(arm.is_script());
        let fields = SheetFields { anchor: true, alg: "mldsa65-ed25519".into(), label: None, fingerprint_hex: "ab".repeat(32), fingerprint_grouped: "abab".into(), seed_grouped: "5e5e 5e5e".into(), account: None, principal: None, origin: None };
        arm.sheet(fields);
        assert!(matches!(arm.confirm("x", "row"), Got::Answer(a) if a == "no"));
        match arm.retype() {
            Got::Answer(Retyped::Typed { seed_hex, fingerprint_prefix }) => {
                assert_eq!(seed_hex, "5e5e5e5e");
                assert_eq!(fingerprint_prefix, "abababab");
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(arm.import(), Got::Abandoned), "a `kept` where an import is asked");
        assert!(matches!(arm.destination(0), Got::Abandoned), "`abandon`");
        assert!(matches!(arm.confirm("y", "r"), Got::Abandoned), "exhausted");
        let said = lines.lock().unwrap().join("\n");
        assert!(said.contains("another moment's kind"), "{said}");
        assert!(said.contains("the script says abandon"), "{said}");
        assert!(said.contains("no answer left"), "{said}");
        assert!(!said.contains("5e5e"), "{said}");
    }
}
