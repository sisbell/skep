//! The CLI's `Person` over the terminal (`client.md` §1.2, §2.4, §5.2):
//! prompts to stderr and answers read from stdin line by line, the sheet as a
//! ruled box on stderr, the dismissal a clear of the screen and its
//! scrollback. THE PERSON DOORS REQUIRE A CONTROLLING TERMINAL and refuse
//! without one (exit 3) — the check is THIS implementation's and never the
//! walk's, so the same walks run under the shell's native windows and the
//! library's scripted person. The realization here is the std streams'
//! `isatty` on BOTH stdin and stderr: a wrapper that captures the one or
//! feeds the other — the wrapper §2.4 names as satisfying every step of the
//! backup moment with no paper and no person — fails it. Every prompt the
//! CLI makes is read through `answer`, those a command that is no person
//! door asks among them, so none reaches stdout.

use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;

use skep_client::person::{Abandoned, Confirmation, Consent, Destination, HandedPath, Import, Imported, KeptOrPlaced, LabelBox, Person, Public, Question, Retype, Retyped, Secret, Sheet, Statement};

/// Whether a controlling terminal stands at both ends of a prompt.
pub fn has_terminal() -> bool {
    io::stdin().is_terminal() && io::stderr().is_terminal()
}

/// `prompt` on stderr, then one answer read from stdin: the line without its
/// line ending, or `None` at the end of input. The one reader every prompt
/// the CLI makes goes through — `Terminal`'s and `bind`'s alike — locking
/// stdin for that one line alone, so a payload or token read with `-` before
/// or after a prompt never waits on a lock a prompt holds.
pub fn answer(prompt: &str) -> io::Result<Option<String>> {
    eprint!("{prompt}");
    let _ = io::stderr().flush();
    let mut line = String::new();
    if io::stdin().read_line(&mut line)? == 0 {
        return Ok(None);
    }
    Ok(Some(line.trim_end_matches(['\n', '\r']).to_string()))
}

/// The terminal person. It holds nothing: every answer is [`answer`]'s.
pub struct Terminal;

/// One answer to a walk's moment, or the person gone — the end of input,
/// or stdin unreadable.
fn line(prompt: &str) -> Result<String, Abandoned> {
    answer(prompt).ok().flatten().ok_or(Abandoned)
}

/// A path, asked again until one is given; `refusal` says why an empty
/// line is no answer.
fn path_line(prompt: &str, refusal: &str) -> Result<PathBuf, Abandoned> {
    loop {
        let p = line(prompt)?;
        if !p.trim().is_empty() {
            return Ok(PathBuf::from(p.trim()));
        }
        eprintln!("{refusal}");
    }
}

/// A seed typed from the print, its whitespace removed — the R42 groups a
/// print shows — and nothing else judged: the walk's `Seed::from_hex`
/// decides it and asks again on a wrong one (AUTH-5.41).
fn seed_line(prompt: &str) -> Result<String, Abandoned> {
    Ok(line(prompt)?.split_whitespace().collect())
}

/// A fingerprint prefix typed from the print, trimmed — the walk's prefix
/// test decides it (AUTH-5.39).
fn prefix_line() -> Result<String, Abandoned> {
    Ok(line("fingerprint prefix from the print (at least the first 8 hex): ")?.trim().to_string())
}

/// The anchor import's three ARMS (`client.md` §4a.2 R1): what the person
/// holds.
#[derive(Debug, PartialEq, Eq)]
enum Arm {
    File,
    Print,
    Neither,
}

/// The arm an answer names — `f`, `p` or `n`, or the word — else `None`,
/// asked again: a path or a seed given here names no arm, so neither is
/// ever routed by its look.
fn arm(text: &str) -> Option<Arm> {
    match text.trim().to_ascii_lowercase().as_str() {
        "f" | "file" => Some(Arm::File),
        "p" | "print" => Some(Arm::Print),
        "n" | "neither" => Some(Arm::Neither),
        _ => None,
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
        let answer = line(&prompt)?;
        Ok(if answer.is_empty() { m.0.default.unwrap_or_default() } else { answer })
    }

    fn ask(&mut self, m: Public<Question>) -> Result<String, Abandoned> {
        line(&m.0.text)
    }

    fn yes_no(&mut self, m: Public<Question>) -> Result<bool, Abandoned> {
        loop {
            let a = line(&format!("{} [y/n]: ", m.0.text))?;
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
        line("press return once the sheet is printed: ")?;
        Ok(())
    }

    fn dismiss(&mut self) {
        // Clear the screen and its scrollback (§5.2; §4.2 step 6).
        eprint!("\x1b[2J\x1b[3J\x1b[H");
        let _ = io::stderr().flush();
    }

    fn retype(&mut self, m: Secret<Retype>) -> Result<Retyped, Abandoned> {
        eprintln!("{}", m.0.prompt);
        let seed_hex = seed_line("seed (64 hex, spaces allowed; empty to decline the re-type): ")?;
        if seed_hex.is_empty() {
            return Ok(Retyped::Declined);
        }
        Ok(Retyped::Typed { seed_hex, fingerprint_prefix: prefix_line()? })
    }

    fn destination(&mut self, m: Secret<Destination>) -> Result<PathBuf, Abandoned> {
        eprintln!("{}", m.0.prompt);
        path_line("directory: ", "a directory is required; no default is offered")
    }

    fn confirm_typed(&mut self, m: Consent<Confirmation>) -> Result<String, Abandoned> {
        eprintln!("{}", m.0.text);
        let a = line(&format!("type `{}` to confirm, or `no`: ", m.0.expected))?;
        Ok(a.trim().to_string())
    }

    /// The import: the ARM is the person's answer, asked first — the kept
    /// FILE, the PRINT, or NEITHER — and never a guess from the text, where
    /// a seed with one character wrong looks like a path. The typed seed
    /// (its whitespace removed) and prefix (trimmed) go to the walk with
    /// nothing else judged: its `Seed::from_hex` and prefix test judge them
    /// and ask again on a wrong one (AUTH-5.39, AUTH-5.41).
    fn import(&mut self, m: Secret<Import>) -> Result<Imported, Abandoned> {
        eprintln!("{}", m.0.prompt);
        loop {
            match arm(&line("which do you hold: the kept FILE (f), the PRINT (p), or NEITHER (n)? ")?) {
                Some(Arm::File) => return Ok(Imported::File(path_line("the file's path: ", "a path is required")?)),
                Some(Arm::Print) => {
                    let seed_hex = seed_line("the seed's 64 hex from the print (spaces allowed): ")?;
                    return Ok(Imported::Typed { seed_hex, fingerprint_prefix: prefix_line()? });
                }
                Some(Arm::Neither) => return Ok(Imported::Neither),
                None => eprintln!("answer f, p or n"),
            }
        }
    }

    fn kept_or_placed(&mut self, m: Secret<HandedPath>) -> Result<KeptOrPlaced, Abandoned> {
        eprintln!("{}", m.0.text);
        loop {
            let a = line(&format!("is {} the KEPT artifact (k) or a PLACED copy (p)? ", m.0.path.display()))?;
            match a.trim().to_ascii_lowercase().as_str() {
                "k" | "kept" => return Ok(KeptOrPlaced::Kept),
                "p" | "placed" => return Ok(KeptOrPlaced::Placed),
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
}
