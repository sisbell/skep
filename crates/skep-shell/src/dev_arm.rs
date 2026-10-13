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
//! A script's answers are `script`'s grammar, parsed by the transport that
//! read the file and handed in as `ArmConfig::Script`.
//!
//! A moment the script has no line for, or a line of another moment's
//! kind, ABANDONS the walk — said so, never a panic: the provider serves
//! on.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Mutex;

use skep_client::person::{Abandoned, Imported, KeptOrPlaced, Retyped};
use skep_client::sheet::SheetFields;

use crate::script::Answer;
use crate::Talk;

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

    /// The script's answer for `moment`, or `None` where no script runs (the
    /// auto arm); `Abandon` and an exhausted script answer the abandonment.
    fn scripted(&self, moment: &str) -> Option<Result<Answer, Abandoned>> {
        let Kind::Script(answers) = &self.kind else { return None };
        let answer = answers.lock().expect("the script's lock").pop_front();
        Some(match answer {
            None => {
                self.say(format!("{moment}: the script has no answer left — the walk is abandoned"));
                Err(Abandoned)
            }
            Some(Answer::Abandon) => {
                self.say(format!("{moment}: the script says abandon"));
                Err(Abandoned)
            }
            Some(a) => Ok(a),
        })
    }

    /// A script answer of another moment's kind: said, and the walk
    /// abandoned — whatever answer the moment asked for.
    fn wrong_kind<T>(&self, moment: &str, got: &Answer) -> Result<T, Abandoned> {
        self.say(format!("{moment}: the script's next answer {got:?} is of another moment's kind — the walk is abandoned"));
        Err(Abandoned)
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

    /// The seed and the fingerprint's first eight hex digits off the `n`-th
    /// sheet shown — `None` where no sheet `n` was shown, or its fingerprint
    /// is shorter than the prefix a typed answer carries.
    fn off_sheet(&self, n: usize) -> Option<(String, String)> {
        let sheets = self.sheets.lock().expect("the sheets' lock");
        let sheet = sheets.get(n)?;
        let prefix = sheet.fingerprint_hex.get(..8)?;
        Some((sheet.seed_grouped.split_whitespace().collect(), prefix.to_string()))
    }

    /// THE RE-TYPE (SECRET): the auto arm declines it; a script types it off
    /// a sheet shown, types it wrong, or declines.
    pub fn retype(&self) -> Result<Retyped, Abandoned> {
        let Some(scripted) = self.scripted("the re-type") else {
            self.say("the re-type is declined (the auto arm types no seed)".to_string());
            return Ok(Retyped::Declined);
        };
        match scripted? {
            Answer::RetypeSheet(n) => match self.off_sheet(n) {
                Some((seed_hex, fingerprint_prefix)) => {
                    self.say(format!("the re-type is typed off sheet {n}"));
                    Ok(Retyped::Typed { seed_hex, fingerprint_prefix })
                }
                None => {
                    self.say(format!("the re-type names sheet {n}, which no sheet shown can type — the walk is abandoned"));
                    Err(Abandoned)
                }
            },
            Answer::RetypeWrong => {
                self.say("the re-type is typed wrong, on purpose".to_string());
                Ok(Retyped::Typed { seed_hex: "00".repeat(32), fingerprint_prefix: "00000000".into() })
            }
            Answer::RetypeDeclined => {
                self.say("the re-type is declined".to_string());
                Ok(Retyped::Declined)
            }
            other => self.wrong_kind("the re-type", &other),
        }
    }

    /// ONE ANCHOR FILE's DESTINATION (SECRET): the auto arm places anchor
    /// `which` under its own directory; a script names a path.
    pub fn destination(&self, which: usize) -> Result<PathBuf, Abandoned> {
        let Some(scripted) = self.scripted("the destination") else {
            let Kind::Auto { anchors } = &self.kind else { unreachable!("the auto arm answers no script") };
            let dir = anchors.join(format!("anchor-{which}"));
            self.say(format!("anchor {which} is placed under {}", dir.display()));
            return Ok(dir);
        };
        match scripted? {
            Answer::Destination(p) => {
                self.say(format!("anchor {which} is placed under {}", p.display()));
                Ok(p)
            }
            other => self.wrong_kind("the destination", &other),
        }
    }

    /// A TYPED CONFIRMATION (CONSENT): the auto arm types the row asked
    /// for; a script types the row, `no`, or its own text.
    pub fn confirm(&self, text: &str, expected: &str) -> Result<String, Abandoned> {
        let Some(scripted) = self.scripted("the confirmation") else {
            self.say(format!("the confirmation `{text}` is typed as asked ({expected})"));
            return Ok(expected.to_string());
        };
        match scripted? {
            Answer::Confirm(true) => {
                self.say(format!("the confirmation `{text}` is typed as asked ({expected})"));
                Ok(expected.to_string())
            }
            Answer::Confirm(false) => {
                self.say(format!("the confirmation `{text}` is answered no"));
                Ok("no".to_string())
            }
            Answer::Typed(t) => {
                self.say(format!("the confirmation `{text}` is answered `{t}`"));
                Ok(t)
            }
            other => self.wrong_kind("the confirmation", &other),
        }
    }

    /// THE ANCHOR IMPORT (SECRET): the auto arm holds neither; a script
    /// hands a file, types off a sheet, types its own, or holds neither.
    pub fn import(&self) -> Result<Imported, Abandoned> {
        let Some(scripted) = self.scripted("the import") else {
            self.say("the import answers neither (the auto arm holds no artifact)".to_string());
            return Ok(Imported::Neither);
        };
        match scripted? {
            Answer::ImportFile(p) => {
                self.say(format!("the import hands the file {}", p.display()));
                Ok(Imported::File(p))
            }
            Answer::ImportSheet(n) => match self.off_sheet(n) {
                Some((seed_hex, fingerprint_prefix)) => {
                    self.say(format!("the import is typed off sheet {n}"));
                    Ok(Imported::Typed { seed_hex, fingerprint_prefix })
                }
                None => {
                    self.say(format!("the import names sheet {n}, which no sheet shown can type — the walk is abandoned"));
                    Err(Abandoned)
                }
            },
            Answer::ImportTyped { seed_hex, fingerprint_prefix } => {
                self.say("the import is typed from the script".to_string());
                Ok(Imported::Typed { seed_hex, fingerprint_prefix })
            }
            Answer::ImportNeither => {
                self.say("the import answers neither".to_string());
                Ok(Imported::Neither)
            }
            other => self.wrong_kind("the import", &other),
        }
    }

    /// KEPT OR PLACED (SECRET): the auto arm answers kept; a script says.
    pub fn kept_or_placed(&self, path: &std::path::Path) -> Result<KeptOrPlaced, Abandoned> {
        let Some(scripted) = self.scripted("kept-or-placed") else {
            self.say(format!("{} is answered kept", path.display()));
            return Ok(KeptOrPlaced::Kept);
        };
        match scripted? {
            Answer::Kept => {
                self.say(format!("{} is answered kept", path.display()));
                Ok(KeptOrPlaced::Kept)
            }
            Answer::Placed => {
                self.say(format!("{} is answered placed", path.display()));
                Ok(KeptOrPlaced::Placed)
            }
            other => self.wrong_kind("kept-or-placed", &other),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    fn talk() -> (Talk, Arc<Mutex<Vec<String>>>) {
        let lines = Arc::new(Mutex::new(Vec::new()));
        let kept = Arc::clone(&lines);
        (Arc::new(move |l: &str| kept.lock().unwrap().push(l.to_string())), lines)
    }

    /// The auto arm answers each SECRET and CONSENT moment as a developer
    /// would and says so; the seed never reaches the TALK stream.
    #[test]
    fn the_auto_arm_answers_and_says_what_it_did_without_the_seed() {
        let (talk, lines) = talk();
        let arm = DevArm::auto(PathBuf::from("/tmp/anchors"), talk);
        let fields = SheetFields { anchor: true, alg: "mldsa65-ed25519".into(), label: None, fingerprint_hex: "ab".repeat(32), fingerprint_grouped: "abab abab".into(), seed_grouped: "5e5e 5e5e".into(), account: None, principal: None, origin: None };
        arm.sheet(fields);
        assert!(matches!(arm.retype(), Ok(Retyped::Declined)));
        assert!(matches!(arm.destination(1), Ok(p) if p == PathBuf::from("/tmp/anchors/anchor-1")));
        assert!(matches!(arm.confirm("retire?", "abcd efgh"), Ok(row) if row == "abcd efgh"));
        assert!(matches!(arm.import(), Ok(Imported::Neither)));
        assert!(matches!(arm.kept_or_placed(std::path::Path::new("/tmp/k")), Ok(KeptOrPlaced::Kept)));
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
        assert!(matches!(arm.confirm("x", "row"), Ok(a) if a == "no"));
        match arm.retype() {
            Ok(Retyped::Typed { seed_hex, fingerprint_prefix }) => {
                assert_eq!(seed_hex, "5e5e5e5e");
                assert_eq!(fingerprint_prefix, "abababab");
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(arm.import(), Err(Abandoned)), "a `kept` where an import is asked");
        assert!(matches!(arm.destination(0), Err(Abandoned)), "`abandon`");
        assert!(matches!(arm.confirm("y", "r"), Err(Abandoned)), "exhausted");
        let said = lines.lock().unwrap().join("\n");
        assert!(said.contains("another moment's kind"), "{said}");
        assert!(said.contains("the script says abandon"), "{said}");
        assert!(said.contains("no answer left"), "{said}");
        assert!(!said.contains("5e5e"), "{said}");
    }

    /// A script's typed import met by another moment abandons the walk, and
    /// the answer it names on TALK carries no seed.
    #[test]
    fn a_typed_import_of_the_wrong_kind_says_no_seed() {
        let (talk, lines) = talk();
        let arm = DevArm::script(vec![Answer::ImportTyped { seed_hex: "5e".repeat(32), fingerprint_prefix: "abcdabcd".into() }], talk);
        assert_eq!(arm.confirm("retire?", "abcd"), Err(Abandoned));
        let said = lines.lock().unwrap().join("\n");
        assert!(said.contains("another moment's kind") && said.contains("ImportTyped"), "{said}");
        assert!(!said.contains("5e5e"), "the seed never reaches TALK: {said}");
    }

    /// A sheet whose fingerprint is shorter than the prefix a typed answer
    /// carries — `SheetFields` is another crate's, filled by its walks —
    /// abandons a re-type or an import typed off it, never a panic at a slice.
    #[test]
    fn a_sheet_too_short_to_type_off_abandons_the_walk() {
        for answer in [Answer::RetypeSheet(0), Answer::ImportSheet(0)] {
            let (talk, _) = talk();
            let arm = DevArm::script(vec![answer.clone()], talk);
            arm.sheet(SheetFields {
                anchor: true,
                alg: "mldsa65-ed25519".into(),
                label: None,
                fingerprint_hex: "ab".into(),
                fingerprint_grouped: "ab".into(),
                seed_grouped: "5e5e".into(),
                account: None,
                principal: None,
                origin: None,
            });
            let typed = if matches!(answer, Answer::RetypeSheet(_)) { arm.retype().map(drop) } else { arm.import().map(drop) };
            assert_eq!(typed, Err(Abandoned), "{answer:?}");
        }
    }

    /// Two sheets shown to `arm`: seeds `5e5e 5e5e` and `6f6f 6f6f`, under
    /// fingerprints of `ab` and of `cd`.
    fn show_two_sheets(arm: &DevArm) {
        for (seed, fingerprint) in [("5e5e 5e5e", "ab"), ("6f6f 6f6f", "cd")] {
            let fields = SheetFields { anchor: true, alg: "mldsa65-ed25519".into(), label: None, fingerprint_hex: fingerprint.repeat(32), fingerprint_grouped: fingerprint.repeat(2), seed_grouped: seed.into(), account: None, principal: None, origin: None };
            arm.sheet(fields);
        }
    }

    /// What a moment answered, a typed seed spelled out — never through
    /// `Debug`, which hides it.
    #[derive(Debug, PartialEq)]
    enum Said {
        Typed(String, String),
        Declined,
        Path(PathBuf),
        Row(String),
        File(PathBuf),
        Neither,
        Kept,
        Placed,
        Abandoned,
    }

    /// The five moments the arm answers.
    const MOMENTS: [&str; 5] = ["retype", "destination", "confirm", "import", "kept_or_placed"];

    /// `moment` asked of `arm`, its answer spelled.
    fn ask(arm: &DevArm, moment: &str) -> Said {
        let said = match moment {
            "retype" => arm.retype().map(|r| match r {
                Retyped::Typed { seed_hex, fingerprint_prefix } => Said::Typed(seed_hex, fingerprint_prefix),
                Retyped::Declined => Said::Declined,
            }),
            "destination" => arm.destination(1).map(Said::Path),
            "confirm" => arm.confirm("retire?", "row").map(Said::Row),
            "import" => arm.import().map(|i| match i {
                Imported::File(p) => Said::File(p),
                Imported::Typed { seed_hex, fingerprint_prefix } => Said::Typed(seed_hex, fingerprint_prefix),
                Imported::Neither => Said::Neither,
            }),
            _ => arm.kept_or_placed(std::path::Path::new("/tmp/k")).map(|k| match k {
                KeptOrPlaced::Kept => Said::Kept,
                KeptOrPlaced::Placed => Said::Placed,
            }),
        };
        said.unwrap_or(Said::Abandoned)
    }

    /// EVERY SCRIPTED ANSWER MEETS EVERY MOMENT as the grammar says, the law
    /// over the seventeen answers and the five moments: an answer meets its
    /// own moment as its line reads — a re-type or an import typed off the
    /// very sheet it names, a sheet never shown abandoning — and abandons
    /// every other, `abandon` every one; and no seed shown or typed reaches
    /// TALK (the mutants that answer one kind as another, take another
    /// moment's answer, or type off the wrong sheet).
    #[test]
    fn every_scripted_answer_meets_every_moment_as_the_grammar_says() {
        let typed = |seed: &str, prefix: &str| Said::Typed(seed.into(), prefix.into());
        let cells = [
            (Answer::Confirm(true), "confirm", Said::Row("row".into())),
            (Answer::Confirm(false), "confirm", Said::Row("no".into())),
            (Answer::Typed("a wrong row".into()), "confirm", Said::Row("a wrong row".into())),
            (Answer::RetypeSheet(0), "retype", typed("5e5e5e5e", "abababab")),
            (Answer::RetypeSheet(1), "retype", typed("6f6f6f6f", "cdcdcdcd")),
            (Answer::RetypeSheet(2), "retype", Said::Abandoned),
            (Answer::RetypeWrong, "retype", typed(&"00".repeat(32), "00000000")),
            (Answer::RetypeDeclined, "retype", Said::Declined),
            (Answer::Destination("/tmp/a".into()), "destination", Said::Path("/tmp/a".into())),
            (Answer::ImportFile("/tmp/f".into()), "import", Said::File("/tmp/f".into())),
            (Answer::ImportSheet(0), "import", typed("5e5e5e5e", "abababab")),
            (Answer::ImportSheet(2), "import", Said::Abandoned),
            (Answer::ImportTyped { seed_hex: "7a".repeat(32), fingerprint_prefix: "abcdabcd".into() }, "import", typed(&"7a".repeat(32), "abcdabcd")),
            (Answer::ImportNeither, "import", Said::Neither),
            (Answer::Kept, "kept_or_placed", Said::Kept),
            (Answer::Placed, "kept_or_placed", Said::Placed),
            (Answer::Abandon, "every moment", Said::Abandoned),
        ];
        let abandoned = Said::Abandoned;
        for (answer, own, said) in &cells {
            for moment in MOMENTS {
                let (talk, lines) = talk();
                let arm = DevArm::script(vec![answer.clone()], talk);
                show_two_sheets(&arm);
                let want = if moment == *own { said } else { &abandoned };
                assert_eq!(&ask(&arm, moment), want, "{answer:?} met at {moment}");
                let talked = lines.lock().unwrap().join("\n");
                assert!(!["5e5e", "6f6f", "7a7a"].iter().any(|seed| talked.contains(seed)), "{answer:?} at {moment}, a seed on TALK: {talked}");
            }
        }
    }
}
