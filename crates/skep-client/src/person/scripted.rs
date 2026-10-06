//! THE SCRIPTED PERSON — the library's test support (§2.4, §8): the seam a
//! test drives, never the CLI. Answers come off a script in order; every
//! moment is recorded in the transcript; the sheet's fields are kept so a
//! re-type can come "off the paper" — or be wrong on purpose. An answer of
//! the wrong kind for its moment panics: the script is the test's own.
//!
//! Compiled only under `test-hooks` (and this crate's own `cfg(test)`): a
//! suite turns the feature on, a build that compiles no test carries none
//! of it, and `tests/it/tidy.rs` checks the gate on its `mod` line.

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
    /// A confirmation: `true` types the row asked for, `false` types `no`.
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
