//! The `Person` seam (`client.md` §1.1's `person` row; §5): the human
//! moments as calls the embedder answers, in THREE CLASSES the trait marks
//! AS TYPES (RULED, owner 2026-09-09 "take the split"; the third class
//! 2026-10-04, cs6-1; §9 item 42):
//!
//! * SECRET moments carry key material — the sheet, the re-type, the anchor
//!   file's destination, the import, kept-or-placed — and the embedder
//!   answers them in its own hands, never a page;
//! * CONSENT moments are public data answered in the SHELL's OWN WINDOW:
//!   every comparison and confirmation that gates a permanent credential
//!   act, which the surface that issued the act never answers;
//! * PUBLIC moments carry neither — the statements, the boxes, the display
//!   name, every question over public facts — and may be forwarded.
//!
//! The generic "forward every moment" embedder becomes UNWRITABLE: routing
//! is chosen per class. Nothing inspects the SURFACE — the obligation is
//! named where an embedder must meet it. `dismiss` is a SECRET moment's
//! close (§4.2 step 6): the exported material is no longer displayed at this
//! surface and not recoverable from it. The walks require a `Person`, never
//! a terminal: the CLI's `Person` checks for one, the shell's answers in
//! native windows, and [`scripted::Scripted`] is the seam a test drives.

use std::fmt;
use std::path::PathBuf;

use crate::sheet::SheetFields;

/// A PUBLIC moment's payload: no key material; may be forwarded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Public<T>(pub T);

/// A SECRET moment's payload: carries, or asks for, key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Secret<T>(pub T);

/// A CONSENT moment's payload: public data gating a permanent credential
/// act, answered in the embedder's own hands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Consent<T>(pub T);

/// A pinned statement, with the rule it renders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Statement {
    pub rule: &'static str,
    pub text: String,
}

/// A name box (AUTH-5.42): the box's statements, a default where the box
/// offers one, and — where the name is already fixed and only SHOWN — the
/// fixed name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabelBox {
    pub title: String,
    pub statements: Vec<String>,
    pub default: Option<String>,
}

/// A question over public facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub text: String,
}

/// The paper path's sheet: the field list (AUTH-5.38) with the seed grouped
/// (AUTH-5.1) — SECRET.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sheet {
    pub fields: SheetFields,
}

/// The re-type from the print (AUTH-5.41: "the 64 hex typed once") —
/// SECRET.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Retype {
    pub prompt: String,
}

/// The re-type's answer: the hex and a fingerprint prefix of at least one
/// R42 group (§9 item 35), or the re-type DECLINED (§4.2 step 9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Retyped {
    Typed { seed_hex: String, fingerprint_prefix: String },
    Declined,
}

/// Where to write one anchor file (§4.2 step 4; §6): asked once per
/// anchor, NO default offered — SECRET, the destination being where key
/// material lands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    pub prompt: String,
    pub which: usize,
}

/// A typed confirmation gating a permanent act — CONSENT: the person types
/// `expected` (the ROW — a fingerprint's first R42 group — where a row is
/// what the act names, AUTH-5.46) or `no`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Confirmation {
    pub text: String,
    pub expected: String,
}

/// THE ANCHOR IMPORT (`client.md` §4a.2 R1) — SECRET: the artifact handed
/// in, a FILE picked from disk, the 64 hex TYPED from a print with a
/// fingerprint prefix of at least one R42 group (§9 item 35), or "I hold
/// NEITHER" — an ANSWER and never an error (AUTH-5.16's no-artifact arm).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Import {
    pub prompt: String,
    /// Whether a file may be named at this moment (the flag already named
    /// one where false).
    pub file_allowed: bool,
}

/// The import's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Imported {
    File(PathBuf),
    Typed { seed_hex: String, fingerprint_prefix: String },
    Neither,
}

/// KEPT OR PLACED (AUTH-5.54 step 3's file arm) — SECRET: whether the
/// handed path is the KEPT artifact (retained) or a PLACED copy (destroyed
/// when the ceremony ends); "kept-or-placed is not a filesystem-readable
/// property of a path", so the person answers what no read can.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeptOrPlaced {
    pub path: PathBuf,
    pub text: String,
}

/// The custody answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Custody {
    Kept,
    Placed,
}

/// The person left: an EOF, a Ctrl-C, a window closed — the walk takes its
/// own abandonment exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Abandoned;

impl fmt::Display for Abandoned {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the person abandoned the walk")
    }
}

/// THE SEAM.
pub trait Person {
    /// A statement, said (PUBLIC).
    fn say(&mut self, m: Public<Statement>);
    /// A name box, answered (PUBLIC) — the box's own domain test is the
    /// walk's, which re-asks on a refusal.
    fn label(&mut self, m: Public<LabelBox>) -> Result<String, Abandoned>;
    /// A question over public facts, answered in text (PUBLIC).
    fn ask(&mut self, m: Public<Question>) -> Result<String, Abandoned>;
    /// A yes-or-no question over public facts (PUBLIC).
    fn yes_no(&mut self, m: Public<Question>) -> Result<bool, Abandoned>;
    /// The sheet, displayed (SECRET).
    fn sheet(&mut self, m: Secret<Sheet>) -> Result<(), Abandoned>;
    /// The SECRET moment's close: whatever was displayed is no longer, at
    /// this surface, and not recoverable from it (§4.2 step 6).
    fn dismiss(&mut self);
    /// The re-type from the print (SECRET).
    fn retype(&mut self, m: Secret<Retype>) -> Result<Retyped, Abandoned>;
    /// One anchor file's destination (SECRET).
    fn destination(&mut self, m: Secret<Destination>) -> Result<PathBuf, Abandoned>;
    /// A typed confirmation (CONSENT): `true` iff the person typed
    /// `expected`.
    fn confirm(&mut self, m: Consent<Confirmation>) -> Result<bool, Abandoned>;
    /// A typed confirmation ANSWERED IN TEXT (CONSENT), so a walk can tell
    /// `no` from a wrong row and re-ask the row (AUTH-5.46: "the wrong row
    /// is the mistake stress produces"). The default answers `expected` or
    /// `no` off [`Person::confirm`]; an embedder that reads the text answers
    /// it verbatim.
    fn confirm_typed(&mut self, m: Consent<Confirmation>) -> Result<String, Abandoned> {
        let expected = m.0.expected.clone();
        Ok(if self.confirm(m)? { expected } else { "no".to_string() })
    }
    /// THE ANCHOR IMPORT (SECRET): a file, the typed hex, or neither.
    fn import(&mut self, m: Secret<Import>) -> Result<Imported, Abandoned>;
    /// KEPT OR PLACED (SECRET): the handed file's custody.
    fn custody(&mut self, m: Secret<KeptOrPlaced>) -> Result<Custody, Abandoned>;
}

pub mod scripted {
    //! THE SCRIPTED PERSON — the library's test support (§2.4, §8): the seam a
    //! test drives, never the CLI. Answers come off a script in order; every
    //! moment is recorded in the transcript; the sheet's fields are kept so a
    //! re-type can come "off the paper" — or be wrong on purpose.

    use std::collections::VecDeque;
    use std::path::PathBuf;

    use super::*;

    /// One scripted answer.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Script {
        /// The box's default, or this text where the box offers none.
        LabelDefault,
        /// This label.
        Label(String),
        /// A question's text answer.
        Answer(String),
        /// A yes-or-no.
        YesNo(bool),
        /// A confirmation.
        Confirm(bool),
        /// The re-type, read off the n-th sheet shown (the paper), counted
        /// from zero.
        RetypeFromSheet(usize),
        /// A re-type of the wrong hex — a mistyped paper.
        RetypeWrong,
        /// The re-type declined.
        RetypeDeclined,
        /// An anchor file's destination.
        Destination(PathBuf),
        /// A typed confirmation answered in TEXT — a wrong row, on purpose.
        Typed(String),
        /// The import: a file.
        ImportFile(PathBuf),
        /// The import: the hex typed off the n-th sheet shown, with its
        /// fingerprint's first group.
        ImportFromSheet(usize),
        /// The import: this hex and this prefix, as typed.
        ImportTyped { seed_hex: String, fingerprint_prefix: String },
        /// The import: "I hold neither".
        ImportNeither,
        /// Kept or placed.
        Custody(Custody),
        /// The person leaves at this moment.
        Abandon,
    }

    /// The scripted person.
    #[derive(Debug, Default)]
    pub struct Scripted {
        script: VecDeque<Script>,
        /// Every moment, in order, as a line: the class, the kind, the text.
        pub transcript: Vec<String>,
        /// Every sheet shown — the SECRET material the test is allowed to
        /// see, since it stands for the paper.
        pub sheets: Vec<SheetFields>,
        /// The dismissals, counted.
        pub dismissed: usize,
    }

    impl Scripted {
        /// A person who will answer `script`, in order.
        pub fn new(script: Vec<Script>) -> Scripted {
            Scripted { script: script.into(), ..Scripted::default() }
        }

        /// Whether the transcript carries `needle`.
        pub fn said(&self, needle: &str) -> bool {
            self.transcript.iter().any(|l| l.contains(needle))
        }

        fn next(&mut self, what: &str) -> Result<Script, Abandoned> {
            match self.script.pop_front() {
                Some(Script::Abandon) | None => {
                    self.transcript.push(format!("ABANDON at {what}"));
                    Err(Abandoned)
                }
                Some(s) => Ok(s),
            }
        }
    }

    impl Person for Scripted {
        fn say(&mut self, m: Public<Statement>) {
            self.transcript.push(format!("PUBLIC say [{}]: {}", m.0.rule, m.0.text));
        }

        fn label(&mut self, m: Public<LabelBox>) -> Result<String, Abandoned> {
            self.transcript.push(format!("PUBLIC label [{}]: {}", m.0.title, m.0.statements.join(" | ")));
            match self.next("label")? {
                Script::LabelDefault => Ok(m.0.default.unwrap_or_else(|| "default".into())),
                Script::Label(l) => Ok(l),
                other => panic!("the script answered a label box with {other:?}"),
            }
        }

        fn ask(&mut self, m: Public<Question>) -> Result<String, Abandoned> {
            self.transcript.push(format!("PUBLIC ask: {}", m.0.text));
            match self.next("ask")? {
                Script::Answer(a) => Ok(a),
                other => panic!("the script answered a question with {other:?}"),
            }
        }

        fn yes_no(&mut self, m: Public<Question>) -> Result<bool, Abandoned> {
            self.transcript.push(format!("PUBLIC yes_no: {}", m.0.text));
            match self.next("yes_no")? {
                Script::YesNo(b) => Ok(b),
                other => panic!("the script answered a yes/no with {other:?}"),
            }
        }

        fn sheet(&mut self, m: Secret<Sheet>) -> Result<(), Abandoned> {
            self.transcript.push(format!("SECRET sheet: fingerprint {}", m.0.fields.fingerprint_hex));
            self.sheets.push(m.0.fields);
            Ok(())
        }

        fn dismiss(&mut self) {
            self.transcript.push("SECRET dismiss".into());
            self.dismissed += 1;
        }

        fn retype(&mut self, m: Secret<Retype>) -> Result<Retyped, Abandoned> {
            self.transcript.push(format!("SECRET retype: {}", m.0.prompt));
            match self.next("retype")? {
                Script::RetypeFromSheet(n) => {
                    let sheet = self.sheets.get(n).expect("that sheet was shown before the re-type");
                    Ok(Retyped::Typed {
                        seed_hex: sheet.seed_grouped.split_whitespace().collect(),
                        fingerprint_prefix: sheet.fingerprint_hex[..8].to_string(),
                    })
                }
                Script::RetypeWrong => Ok(Retyped::Typed { seed_hex: "00".repeat(32), fingerprint_prefix: "00000000".into() }),
                Script::RetypeDeclined => Ok(Retyped::Declined),
                other => panic!("the script answered a re-type with {other:?}"),
            }
        }

        fn destination(&mut self, m: Secret<Destination>) -> Result<PathBuf, Abandoned> {
            self.transcript.push(format!("SECRET destination {}: {}", m.0.which, m.0.prompt));
            match self.next("destination")? {
                Script::Destination(p) => Ok(p),
                other => panic!("the script answered a destination with {other:?}"),
            }
        }

        fn confirm(&mut self, m: Consent<Confirmation>) -> Result<bool, Abandoned> {
            self.transcript.push(format!("CONSENT confirm: {}", m.0.text));
            match self.next("confirm")? {
                Script::Confirm(b) => Ok(b),
                Script::Typed(t) => Ok(t == m.0.expected),
                other => panic!("the script answered a confirmation with {other:?}"),
            }
        }

        fn confirm_typed(&mut self, m: Consent<Confirmation>) -> Result<String, Abandoned> {
            self.transcript.push(format!("CONSENT confirm: {}", m.0.text));
            match self.next("confirm")? {
                Script::Confirm(true) => Ok(m.0.expected),
                Script::Confirm(false) => Ok("no".into()),
                Script::Typed(t) => Ok(t),
                other => panic!("the script answered a confirmation with {other:?}"),
            }
        }

        fn import(&mut self, m: Secret<Import>) -> Result<Imported, Abandoned> {
            self.transcript.push(format!("SECRET import: {}", m.0.prompt));
            match self.next("import")? {
                Script::ImportFile(p) => Ok(Imported::File(p)),
                Script::ImportFromSheet(n) => {
                    let sheet = self.sheets.get(n).expect("that sheet was shown before the import");
                    Ok(Imported::Typed {
                        seed_hex: sheet.seed_grouped.split_whitespace().collect(),
                        fingerprint_prefix: sheet.fingerprint_hex[..8].to_string(),
                    })
                }
                Script::ImportTyped { seed_hex, fingerprint_prefix } => Ok(Imported::Typed { seed_hex, fingerprint_prefix }),
                Script::ImportNeither => Ok(Imported::Neither),
                other => panic!("the script answered an import with {other:?}"),
            }
        }

        fn custody(&mut self, m: Secret<KeptOrPlaced>) -> Result<Custody, Abandoned> {
            self.transcript.push(format!("SECRET custody of {}: {}", m.0.path.display(), m.0.text));
            match self.next("custody")? {
                Script::Custody(c) => Ok(c),
                other => panic!("the script answered kept-or-placed with {other:?}"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::scripted::{Script, Scripted};
    use super::*;

    /// The scripted seam answers in order, records every moment with its
    /// class, and abandons where the script says.
    #[test]
    fn the_scripted_person_answers_in_order_and_abandons_on_cue() {
        let mut p = Scripted::new(vec![Script::LabelDefault, Script::YesNo(true), Script::Abandon]);
        p.say(Public(Statement { rule: "AUTH-5.74", text: "local forever".into() }));
        let label = p.label(Public(LabelBox { title: "a".into(), statements: vec![], default: Some("host-a".into()) })).unwrap();
        assert_eq!(label, "host-a");
        assert!(p.yes_no(Public(Question { text: "?".into() })).unwrap());
        assert_eq!(p.ask(Public(Question { text: "name".into() })), Err(Abandoned));
        assert!(p.said("PUBLIC say [AUTH-5.74]"));
        assert!(p.said("ABANDON at ask"));
    }
}
