//! THE DEV ARM's SCRIPT (`client.md` §4b.3, §4b.5): the file a run names,
//! parsed into the answers the dev arm gives the SECRET and CONSENT
//! moments of a ceremony, one per moment in order — the transport reads
//! the file and hands the answers in as
//! [`ArmConfig::Script`](crate::ArmConfig::Script).
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

use std::fmt;
use std::path::PathBuf;

/// One scripted answer. Its `Debug` shows a typed import's seed as `…`, as
/// `skep-client`'s `Imported` does, so no TALK line that names an answer
/// carries a seed.
#[derive(Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
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

impl fmt::Debug for Answer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Answer::Confirm(yes) => f.debug_tuple("Confirm").field(yes).finish(),
            Answer::Typed(text) => f.debug_tuple("Typed").field(text).finish(),
            Answer::RetypeSheet(n) => f.debug_tuple("RetypeSheet").field(n).finish(),
            Answer::RetypeWrong => f.write_str("RetypeWrong"),
            Answer::RetypeDeclined => f.write_str("RetypeDeclined"),
            Answer::Destination(path) => f.debug_tuple("Destination").field(path).finish(),
            Answer::ImportFile(path) => f.debug_tuple("ImportFile").field(path).finish(),
            Answer::ImportSheet(n) => f.debug_tuple("ImportSheet").field(n).finish(),
            Answer::ImportTyped { fingerprint_prefix, .. } => {
                f.debug_struct("ImportTyped").field("seed_hex", &format_args!("…")).field("fingerprint_prefix", fingerprint_prefix).finish()
            }
            Answer::ImportNeither => f.write_str("ImportNeither"),
            Answer::Kept => f.write_str("Kept"),
            Answer::Placed => f.write_str("Placed"),
            Answer::Abandon => f.write_str("Abandon"),
        }
    }
}

/// A script line the grammar refuses: its number and the line — an `import
/// typed` line named by its form alone, since the words after the form may
/// be a seed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptError {
    pub line: usize,
    pub text: String,
}

impl fmt::Display for ScriptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
        let words: Vec<&str> = line.split_whitespace().collect();
        let shown = if words.starts_with(&["import", "typed"]) { "import typed …" } else { line };
        let refused = || ScriptError { line: i + 1, text: shown.to_string() };
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

#[cfg(test)]
mod tests {
    use super::*;

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

    /// A typed import's seed is in no text the script's values print: its
    /// answer's `Debug` shows the seed as `…`, and a refused `import typed`
    /// line is named by its form alone.
    #[test]
    fn a_typed_seed_prints_nowhere() {
        let answers = parse("import typed 5e5e5e5e abcd").unwrap();
        let shown = format!("{answers:?}");
        assert!(shown.contains("ImportTyped") && shown.contains("abcd") && !shown.contains("5e5e"), "{shown}");
        let e = parse("kept\nimport typed 5e5e5e5e\n").unwrap_err();
        assert_eq!((e.line, e.text.as_str()), (2, "import typed …"));
        assert!(!e.to_string().contains("5e5e"), "{e}");
        assert_eq!(format!("{:?}", Answer::RetypeSheet(2)), "RetypeSheet(2)", "every other answer prints as the derive would");
    }
}
