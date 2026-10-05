//! The CLI's `Person` over the terminal (`client.md` §1.2, §2.4, §5.2):
//! prompts to stderr and answers read from stdin line by line, the sheet as a
//! ruled box on stderr, the dismissal a clear of the screen and its
//! scrollback. THE PERSON DOORS REQUIRE A CONTROLLING TERMINAL and refuse
//! without one (exit 3) — the check is THIS implementation's and never the
//! walk's, so the same walks run under the shell's native windows and the
//! library's scripted person. The realization here is the std streams'
//! `isatty` on BOTH stdin and stderr: a wrapper that captures the one or
//! feeds the other — the wrapper §2.4 names as satisfying every step of the
//! backup moment with no paper and no person — fails it.

use std::io::{self, BufRead, IsTerminal, Write};
use std::path::PathBuf;

use skep_client::person::{Abandoned, Confirmation, Consent, Custody, Destination, Import, Imported, KeptOrPlaced, LabelBox, Person, Public, Question, Retype, Retyped, Secret, Sheet, Statement};

/// Whether a controlling terminal stands at both ends of a prompt.
pub fn has_terminal() -> bool {
    io::stdin().is_terminal() && io::stderr().is_terminal()
}

/// The terminal person.
pub struct Terminal {
    stdin: io::StdinLock<'static>,
}

impl Terminal {
    pub fn new() -> Terminal {
        Terminal { stdin: io::stdin().lock() }
    }

    fn line(&mut self, prompt: &str) -> Result<String, Abandoned> {
        eprint!("{prompt}");
        let _ = io::stderr().flush();
        let mut line = String::new();
        match self.stdin.read_line(&mut line) {
            Ok(0) | Err(_) => Err(Abandoned),
            Ok(_) => Ok(line.trim_end_matches(['\n', '\r']).to_string()),
        }
    }
}

/// A ruled box around `lines` on stderr (§5.2: the TERMINAL adds the box and
/// its width to the sheet's field list, the fields the library's).
fn boxed(lines: &[String]) -> String {
    let width = lines.iter().map(|l| l.chars().count()).max().unwrap_or(0).max(20);
    let bar = "─".repeat(width + 2);
    let mut out = format!("┌{bar}┐\n");
    for l in lines {
        let pad = width - l.chars().count();
        out.push_str(&format!("│ {l}{} │\n", " ".repeat(pad)));
    }
    out.push_str(&format!("└{bar}┘\n"));
    out
}

impl Person for Terminal {
    fn say(&mut self, m: Public<Statement>) {
        eprintln!("[{}] {}", m.0.rule, m.0.text);
    }

    fn label(&mut self, m: Public<LabelBox>) -> Result<String, Abandoned> {
        eprintln!("{}:", m.0.title);
        for s in &m.0.statements {
            eprintln!("  {s}");
        }
        let prompt = match &m.0.default {
            Some(d) => format!("{} [{d}]: ", m.0.title),
            None => format!("{}: ", m.0.title),
        };
        let answer = self.line(&prompt)?;
        Ok(if answer.is_empty() { m.0.default.unwrap_or_default() } else { answer })
    }

    fn ask(&mut self, m: Public<Question>) -> Result<String, Abandoned> {
        self.line(&m.0.text)
    }

    fn yes_no(&mut self, m: Public<Question>) -> Result<bool, Abandoned> {
        loop {
            let a = self.line(&format!("{} [y/n]: ", m.0.text))?;
            match a.trim().to_ascii_lowercase().as_str() {
                "y" | "yes" => return Ok(true),
                "n" | "no" => return Ok(false),
                _ => eprintln!("answer y or n"),
            }
        }
    }

    fn sheet(&mut self, m: Secret<Sheet>) -> Result<(), Abandoned> {
        let mut lines = vec!["skep anchor sheet — print this; the seed below is the key".to_string(), String::new()];
        for (name, value) in m.0.fields.lines() {
            let mut parts = value.lines();
            lines.push(format!("{name:<12}{}", parts.next().unwrap_or("")));
            for rest in parts {
                lines.push(format!("{:<12}{rest}", ""));
            }
        }
        eprint!("{}", boxed(&lines));
        let _ = io::stderr().flush();
        self.line("press return once the sheet is printed: ")?;
        Ok(())
    }

    fn dismiss(&mut self) {
        // Clear the screen and its scrollback (§5.2; §4.2 step 6).
        eprint!("\x1b[2J\x1b[3J\x1b[H");
        let _ = io::stderr().flush();
    }

    fn retype(&mut self, m: Secret<Retype>) -> Result<Retyped, Abandoned> {
        eprintln!("{}", m.0.prompt);
        let seed = self.line("seed (64 hex, spaces allowed; empty to decline the re-type): ")?;
        if seed.trim().is_empty() {
            return Ok(Retyped::Declined);
        }
        let prefix = self.line("fingerprint prefix (at least the first 8 hex): ")?;
        Ok(Retyped::Typed { seed_hex: seed.split_whitespace().collect(), fingerprint_prefix: prefix.trim().to_string() })
    }

    fn destination(&mut self, m: Secret<Destination>) -> Result<PathBuf, Abandoned> {
        eprintln!("{}", m.0.prompt);
        loop {
            let p = self.line("directory: ")?;
            if p.trim().is_empty() {
                eprintln!("a directory is required; no default is offered");
                continue;
            }
            return Ok(PathBuf::from(p.trim()));
        }
    }

    fn confirm(&mut self, m: Consent<Confirmation>) -> Result<bool, Abandoned> {
        eprintln!("{}", m.0.text);
        let a = self.line(&format!("type `{}` to confirm: ", m.0.expected))?;
        Ok(a.trim() == m.0.expected)
    }

    fn confirm_typed(&mut self, m: Consent<Confirmation>) -> Result<String, Abandoned> {
        eprintln!("{}", m.0.text);
        let a = self.line(&format!("type `{}` to confirm, or `no`: ", m.0.expected))?;
        Ok(a.trim().to_string())
    }

    /// The import: a line that is `neither`, a path, or 64 hex (spaces
    /// allowed) followed by the fingerprint's first group on a second line.
    fn import(&mut self, m: Secret<Import>) -> Result<Imported, Abandoned> {
        eprintln!("{}", m.0.prompt);
        loop {
            let prompt = if m.0.file_allowed { "anchor (a file path, the 64 hex from the print, or `neither`): " } else { "anchor (the 64 hex from the print, or `neither`): " };
            let a = self.line(prompt)?;
            let text = a.trim();
            if text.is_empty() {
                eprintln!("an answer is required: a path, the hex, or `neither`");
                continue;
            }
            if text.eq_ignore_ascii_case("neither") {
                return Ok(Imported::Neither);
            }
            let compact: String = text.split_whitespace().collect();
            if compact.len() == 64 && compact.bytes().all(|b| b.is_ascii_hexdigit()) {
                let prefix = self.line("fingerprint prefix from the print (at least the first 8 hex): ")?;
                return Ok(Imported::Typed { seed_hex: compact.to_ascii_lowercase(), fingerprint_prefix: prefix.trim().to_ascii_lowercase() });
            }
            if !m.0.file_allowed {
                eprintln!("a file was already named by the flag; type the hex, or `neither`");
                continue;
            }
            return Ok(Imported::File(PathBuf::from(text)));
        }
    }

    fn custody(&mut self, m: Secret<KeptOrPlaced>) -> Result<Custody, Abandoned> {
        eprintln!("{}", m.0.text);
        loop {
            let a = self.line(&format!("is {} the KEPT artifact (k) or a PLACED copy (p)? ", m.0.path.display()))?;
            match a.trim().to_ascii_lowercase().as_str() {
                "k" | "kept" => return Ok(Custody::Kept),
                "p" | "placed" => return Ok(Custody::Placed),
                _ => eprintln!("answer k or p"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_box_is_ruled_to_the_widest_line() {
        let b = boxed(&["ab".into(), "abcd".into()]);
        let lines: Vec<&str> = b.lines().collect();
        assert_eq!(lines.len(), 4);
        assert!(lines[0].starts_with('┌') && lines[3].starts_with('└'));
        assert_eq!(lines[1].chars().count(), lines[2].chars().count());
    }
}
