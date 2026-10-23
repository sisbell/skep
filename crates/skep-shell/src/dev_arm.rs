//! The dev arm: where a ceremony's secret and consent moments go.
//!
//! In the dev provider (`client.md` §4b.3, §4b.5) they come here — the
//! sheet, the re-type, an anchor's destination, the import, kept-or-placed,
//! every typed confirmation — since "the page never sees a seed" and a
//! consent "is answered in the shell's own window and never by the page",
//! and the provider has no window. Two arms: a script read from a file, one
//! answer per line in order (the precedent is `skep-client`'s
//! `person::scripted`, a suite's hands), or the auto arm, which answers each
//! moment the way a developer on a throwaway board would — the confirmation
//! typed, the anchor files placed under the provider's own directory, the
//! re-type declined, no artifact held. Every answer is said on the `Talk`
//! stream, naming the moment and what was done and never the seed: the
//! sheet a walk shows is kept in this process where a script runs, so its
//! `retype sheet` can type it back, and dropped by the auto arm, which types
//! no seed — it leaves the process nowhere. The native statements — those
//! naming where key material rests on disk (§4b.3; `person`'s
//! `NATIVE_RULES`) — are said there too, in the place of the shell's own
//! window, and sent to no page.
//!
//! A script's answers are `script`'s grammar, parsed by the transport that
//! read the file and handed in as `ArmConfig::Script`.
//!
//! A moment the script has no line for, or a line of another moment's
//! kind, abandons the walk — said so, never a panic: the provider serves
//! on.

use std::collections::VecDeque;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use skep_client::person::{Abandoned, Confirmation, Imported, KeptOrPlaced, Retyped, Statement};
use skep_client::sheet::SheetFields;

use crate::script::Answer;
use crate::Talk;

/// The arm's kind: the auto-answer, or a script.
#[derive(Debug)]
enum Kind {
    /// The auto arm, the anchor files' directory.
    Auto { anchors: PathBuf },
    /// The script's answers, taken in order, and the sheets shown so far.
    ///
    /// The sheets are never sent anywhere — kept for a `retype sheet` or an
    /// `import sheet` to type back.
    Script { answers: Mutex<VecDeque<Answer>>, sheets: Mutex<Vec<SheetFields>> },
}

/// What answers a moment: the auto arm, or the script's next answer.
///
/// The auto arm comes with its anchor files' directory beside it.
#[derive(Debug)]
enum Answering<'a> {
    Auto { anchors: &'a Path },
    Script(Answer),
}

/// The dev arm: its kind and the `Talk` sink every answer is said on.
///
/// A script's kind holds the sheets shown so far.
pub struct DevArm {
    kind: Kind,
    talk: Talk,
}

impl fmt::Debug for DevArm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DevArm({})", match &self.kind { Kind::Auto { .. } => "auto", Kind::Script { .. } => "script" })
    }
}

impl DevArm {
    /// Returns the auto arm, its anchor files under `anchors`.
    ///
    /// Every answer is said on `talk`.
    pub fn auto(anchors: PathBuf, talk: Talk) -> DevArm {
        DevArm { kind: Kind::Auto { anchors }, talk }
    }

    /// Returns the script arm over `answers`, every answer said on `talk`.
    pub fn script(answers: Vec<Answer>, talk: Talk) -> DevArm {
        DevArm { kind: Kind::Script { answers: Mutex::new(answers.into()), sheets: Mutex::new(Vec::new()) }, talk }
    }

    /// Returns whether this is the script arm.
    pub fn is_script(&self) -> bool {
        matches!(self.kind, Kind::Script { .. })
    }

    fn say(&self, line: impl fmt::Display) {
        (self.talk)(&format!("dev arm: {line}"));
    }

    /// Returns what answers `moment`: the auto arm or the script's next answer.
    ///
    /// # Errors
    ///
    /// Returns [`Abandoned`] for `Abandon` and for an exhausted script, each
    /// said on `Talk`.
    ///
    /// # Panics
    ///
    /// Panics where the script's lock is poisoned.
    fn answering(&self, moment: &str) -> Result<Answering<'_>, Abandoned> {
        let answers = match &self.kind {
            Kind::Auto { anchors } => return Ok(Answering::Auto { anchors }),
            Kind::Script { answers, .. } => answers,
        };
        // Popped in its own statement, so the lock is let go before anything
        // is said.
        let answer = answers.lock().expect("the script's lock").pop_front();
        match answer {
            None => {
                self.say(format_args!("{moment}: the script has no answer left — the walk is abandoned"));
                Err(Abandoned)
            }
            Some(Answer::Abandon) => {
                self.say(format_args!("{moment}: the script says abandon"));
                Err(Abandoned)
            }
            Some(answer) => Ok(Answering::Script(answer)),
        }
    }

    /// Says a script answer of another moment's kind, abandoning the walk.
    ///
    /// # Errors
    ///
    /// Returns [`Abandoned`] always, whatever answer the moment asked for.
    fn wrong_kind<T>(&self, moment: &str, got: &Answer) -> Result<T, Abandoned> {
        self.say(format_args!("{moment}: the script's next answer {got:?} is of another moment's kind — the walk is abandoned"));
        Err(Abandoned)
    }

    /// Takes the sheet (secret), shown to no one.
    ///
    /// It is kept where a script runs, for its `retype sheet` or `import
    /// sheet` to type back; dropped by the auto arm, which types no seed.
    ///
    /// # Panics
    ///
    /// Panics where the sheets' lock is poisoned.
    pub fn sheet(&self, fields: SheetFields) {
        match &self.kind {
            Kind::Script { sheets, .. } => {
                self.say(format_args!("the sheet for fingerprint {} was shown to no one and kept for a scripted re-type", fields.fingerprint_grouped));
                sheets.lock().expect("the sheets' lock").push(fields);
            }
            Kind::Auto { .. } => self.say(format_args!("the sheet for fingerprint {} was shown to no one and dropped (the auto arm types no seed)", fields.fingerprint_grouped)),
        }
    }

    /// Answers the dismissal (secret): nothing was displayed, nothing to clear.
    pub fn dismiss(&self) {
        self.say("the sheet is dismissed (nothing was displayed)");
    }

    /// Says a native statement (`client.md` §4b.3) under its rule.
    ///
    /// It is the shell's own window's, so it is said on `Talk` and sent to no
    /// page.
    pub fn native(&self, statement: &Statement) {
        self.say(format_args!("{}: {}", statement.rule, statement.text));
    }

    /// Returns the seed and fingerprint prefix off the `n`-th sheet shown.
    ///
    /// The sheet is the `n`-th a script was shown, the prefix its
    /// fingerprint's first eight hex digits — `None` where no sheet `n` was
    /// kept, or its fingerprint is shorter than the prefix a typed answer
    /// carries.
    ///
    /// # Panics
    ///
    /// Panics where the sheets' lock is poisoned.
    fn off_sheet(&self, n: usize) -> Option<(String, String)> {
        let Kind::Script { sheets, .. } = &self.kind else { return None };
        let sheets = sheets.lock().expect("the sheets' lock");
        let sheet = sheets.get(n)?;
        let prefix = sheet.fingerprint_hex.get(..8)?;
        Some((sheet.seed_grouped.as_str().split_whitespace().collect(), prefix.to_string()))
    }

    /// Answers the re-type (secret).
    ///
    /// The auto arm declines it; a script types it off a sheet shown, types
    /// it wrong, or declines.
    ///
    /// # Errors
    ///
    /// Returns [`Abandoned`] where the script abandons or is exhausted, names
    /// a sheet no sheet shown can type, or answers another moment's kind.
    pub fn retype(&self) -> Result<Retyped, Abandoned> {
        match self.answering("the re-type")? {
            Answering::Auto { .. } => {
                self.say("the re-type is declined (the auto arm types no seed)");
                Ok(Retyped::Declined)
            }
            Answering::Script(Answer::RetypeSheet(n)) => match self.off_sheet(n) {
                Some((seed_hex, fingerprint_prefix)) => {
                    self.say(format_args!("the re-type is typed off sheet {n}"));
                    Ok(Retyped::Typed { seed_hex, fingerprint_prefix })
                }
                None => {
                    self.say(format_args!("the re-type names sheet {n}, which no sheet shown can type — the walk is abandoned"));
                    Err(Abandoned)
                }
            },
            Answering::Script(Answer::RetypeWrong) => {
                self.say("the re-type is typed wrong, on purpose");
                Ok(Retyped::Typed { seed_hex: "00".repeat(32), fingerprint_prefix: "00000000".into() })
            }
            Answering::Script(Answer::RetypeDeclined) => {
                self.say("the re-type is declined");
                Ok(Retyped::Declined)
            }
            Answering::Script(other) => self.wrong_kind("the re-type", &other),
        }
    }

    /// Answers one anchor file's destination (secret).
    ///
    /// The auto arm places anchor `which` under its own directory; a script
    /// names a path.
    ///
    /// # Errors
    ///
    /// Returns [`Abandoned`] where the script abandons or is exhausted, or
    /// answers another moment's kind.
    pub fn destination(&self, which: usize) -> Result<PathBuf, Abandoned> {
        let dir = match self.answering("the destination")? {
            Answering::Auto { anchors } => anchors.join(format!("anchor-{which}")),
            Answering::Script(Answer::Destination(dir)) => dir,
            Answering::Script(other) => return self.wrong_kind("the destination", &other),
        };
        self.say(format_args!("anchor {which} is placed under {}", dir.display()));
        Ok(dir)
    }

    /// Answers a typed confirmation (consent).
    ///
    /// The auto arm types the row asked for; a script types the row, `no`,
    /// or its own text.
    ///
    /// # Errors
    ///
    /// Returns [`Abandoned`] where the script abandons or is exhausted, or
    /// answers another moment's kind.
    pub fn confirm(&self, confirmation: &Confirmation) -> Result<String, Abandoned> {
        let Confirmation { text, expected } = confirmation;
        match self.answering("the confirmation")? {
            Answering::Auto { .. } | Answering::Script(Answer::Confirm(true)) => {
                self.say(format_args!("the confirmation `{text}` is typed as asked ({expected})"));
                Ok(expected.clone())
            }
            Answering::Script(Answer::Confirm(false)) => {
                self.say(format_args!("the confirmation `{text}` is answered no"));
                Ok("no".to_string())
            }
            Answering::Script(Answer::Typed(t)) => {
                self.say(format_args!("the confirmation `{text}` is answered `{t}`"));
                Ok(t)
            }
            Answering::Script(other) => self.wrong_kind("the confirmation", &other),
        }
    }

    /// Answers the anchor import (secret).
    ///
    /// The auto arm holds neither; a script hands a file, types off a sheet,
    /// types its own, or holds neither.
    ///
    /// # Errors
    ///
    /// Returns [`Abandoned`] where the script abandons or is exhausted, names
    /// a sheet no sheet shown can type, or answers another moment's kind.
    pub fn import(&self) -> Result<Imported, Abandoned> {
        match self.answering("the import")? {
            Answering::Auto { .. } => {
                self.say("the import answers neither (the auto arm holds no artifact)");
                Ok(Imported::Neither)
            }
            Answering::Script(Answer::ImportFile(p)) => {
                self.say(format_args!("the import hands the file {}", p.display()));
                Ok(Imported::File(p))
            }
            Answering::Script(Answer::ImportSheet(n)) => match self.off_sheet(n) {
                Some((seed_hex, fingerprint_prefix)) => {
                    self.say(format_args!("the import is typed off sheet {n}"));
                    Ok(Imported::Typed { seed_hex, fingerprint_prefix })
                }
                None => {
                    self.say(format_args!("the import names sheet {n}, which no sheet shown can type — the walk is abandoned"));
                    Err(Abandoned)
                }
            },
            Answering::Script(Answer::ImportTyped { seed_hex, fingerprint_prefix }) => {
                self.say("the import is typed from the script");
                Ok(Imported::Typed { seed_hex, fingerprint_prefix })
            }
            Answering::Script(Answer::ImportNeither) => {
                self.say("the import answers neither");
                Ok(Imported::Neither)
            }
            Answering::Script(other) => self.wrong_kind("the import", &other),
        }
    }

    /// Answers kept-or-placed (secret).
    ///
    /// The auto arm answers kept; a script says.
    ///
    /// # Errors
    ///
    /// Returns [`Abandoned`] where the script abandons or is exhausted, or
    /// answers another moment's kind.
    pub fn kept_or_placed(&self, path: &Path) -> Result<KeptOrPlaced, Abandoned> {
        match self.answering("kept-or-placed")? {
            Answering::Auto { .. } | Answering::Script(Answer::Kept) => {
                self.say(format_args!("{} is answered kept", path.display()));
                Ok(KeptOrPlaced::Kept)
            }
            Answering::Script(Answer::Placed) => {
                self.say(format_args!("{} is answered placed", path.display()));
                Ok(KeptOrPlaced::Placed)
            }
            Answering::Script(other) => self.wrong_kind("kept-or-placed", &other),
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

    /// Checks that the auto arm answers and says what it did, never the seed.
    ///
    /// It answers each secret and consent moment as a developer would,
    /// keeping no sheet it is shown; the seed never reaches `Talk`.
    #[test]
    fn the_auto_arm_answers_and_says_what_it_did_without_the_seed() {
        let (talk, lines) = talk();
        let arm = DevArm::auto(PathBuf::from("/tmp/anchors"), talk);
        let fields = SheetFields { anchor: true, alg: "mldsa65-ed25519".into(), label: None, fingerprint_hex: "ab".repeat(32), fingerprint_grouped: "abab abab".into(), seed_grouped: "5e5e 5e5e".into(), account: None, principal: None, origin: None };
        arm.sheet(fields);
        assert!(matches!(arm.retype(), Ok(Retyped::Declined)));
        assert!(matches!(arm.destination(1), Ok(p) if p == PathBuf::from("/tmp/anchors/anchor-1")));
        assert!(matches!(arm.confirm(&Confirmation { text: "retire?".into(), expected: "abcd efgh".into() }), Ok(row) if row == "abcd efgh"));
        assert!(matches!(arm.import(), Ok(Imported::Neither)));
        assert!(matches!(arm.kept_or_placed(std::path::Path::new("/tmp/k")), Ok(KeptOrPlaced::Kept)));
        arm.dismiss();
        let said = lines.lock().unwrap().join("\n");
        assert!(said.contains("dev arm: the sheet for fingerprint abab abab was shown to no one and dropped (the auto arm types no seed)"), "the auto arm keeps no sheet: {said}");
        assert!(!said.contains("5e5e"), "the seed never reaches TALK: {said}");
        assert!(said.contains("anchor 1 is placed under /tmp/anchors/anchor-1"), "{said}");
        assert!(!arm.is_script());
    }

    /// Checks that the script arm answers in order and abandons, never a panic.
    ///
    /// It types a re-type off the sheet shown, and abandons on a wrong kind,
    /// on `abandon`, and when exhausted.
    #[test]
    fn the_script_arm_answers_in_order_and_abandons_on_a_wrong_kind_or_exhaustion() {
        let (talk, lines) = talk();
        let arm = DevArm::script(vec![Answer::Confirm(false), Answer::RetypeSheet(0), Answer::Kept, Answer::Abandon], talk);
        assert!(arm.is_script());
        let fields = SheetFields { anchor: true, alg: "mldsa65-ed25519".into(), label: None, fingerprint_hex: "ab".repeat(32), fingerprint_grouped: "abab".into(), seed_grouped: "5e5e 5e5e".into(), account: None, principal: None, origin: None };
        arm.sheet(fields);
        assert!(matches!(arm.confirm(&Confirmation { text: "x".into(), expected: "row".into() }), Ok(a) if a == "no"));
        match arm.retype() {
            Ok(Retyped::Typed { seed_hex, fingerprint_prefix }) => {
                assert_eq!(seed_hex, "5e5e5e5e");
                assert_eq!(fingerprint_prefix, "abababab");
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(arm.import(), Err(Abandoned)), "a `kept` where an import is asked");
        assert!(matches!(arm.destination(0), Err(Abandoned)), "`abandon`");
        assert!(matches!(arm.confirm(&Confirmation { text: "y".into(), expected: "r".into() }), Err(Abandoned)), "exhausted");
        let said = lines.lock().unwrap().join("\n");
        assert!(said.contains("another moment's kind"), "{said}");
        assert!(said.contains("the script says abandon"), "{said}");
        assert!(said.contains("no answer left"), "{said}");
        assert!(!said.contains("5e5e"), "{said}");
    }

    /// Checks that a script's typed import met by another moment abandons.
    ///
    /// The walk is abandoned, and the answer named on `Talk` carries no seed.
    #[test]
    fn a_typed_import_of_the_wrong_kind_says_no_seed() {
        let (talk, lines) = talk();
        let arm = DevArm::script(vec![Answer::ImportTyped { seed_hex: "5e".repeat(32), fingerprint_prefix: "abcdabcd".into() }], talk);
        assert_eq!(arm.confirm(&Confirmation { text: "retire?".into(), expected: "abcd".into() }), Err(Abandoned));
        let said = lines.lock().unwrap().join("\n");
        assert!(said.contains("another moment's kind") && said.contains("ImportTyped"), "{said}");
        assert!(!said.contains("5e5e"), "the seed never reaches TALK: {said}");
    }

    /// Checks that a sheet too short to type off abandons the walk.
    ///
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

    /// Shows `arm` two sheets: seeds `5e5e 5e5e` and `6f6f 6f6f`.
    ///
    /// They stand under fingerprints of `ab` and of `cd`.
    fn show_two_sheets(arm: &DevArm) {
        for (seed, fingerprint) in [("5e5e 5e5e", "ab"), ("6f6f 6f6f", "cd")] {
            let fields = SheetFields { anchor: true, alg: "mldsa65-ed25519".into(), label: None, fingerprint_hex: fingerprint.repeat(32), fingerprint_grouped: fingerprint.repeat(2), seed_grouped: seed.into(), account: None, principal: None, origin: None };
            arm.sheet(fields);
        }
    }

    /// What a moment answered, a typed seed spelled out.
    ///
    /// It is never read through `Debug`, which hides the seed.
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

    /// Asks `moment` of `arm`, its answer spelled.
    fn ask(arm: &DevArm, moment: &str) -> Said {
        let said = match moment {
            "retype" => arm.retype().map(|r| match r {
                Retyped::Typed { seed_hex, fingerprint_prefix } => Said::Typed(seed_hex, fingerprint_prefix),
                Retyped::Declined => Said::Declined,
            }),
            "destination" => arm.destination(1).map(Said::Path),
            "confirm" => arm.confirm(&Confirmation { text: "retire?".into(), expected: "row".into() }).map(Said::Row),
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

    /// Checks every scripted answer against every moment, as the grammar says.
    ///
    /// It is the law over the seventeen answers and the five moments: an
    /// answer meets its own moment as its line reads — a re-type or an import
    /// typed off the very sheet it names, a sheet never shown abandoning — and
    /// abandons every other, `abandon` every one; and no seed shown or typed
    /// reaches `Talk` (the mutants that answer one kind as another, take
    /// another moment's answer, or type off the wrong sheet).
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
