//! The CLI's `Person` over the terminal (`client.md` §1.2, §2.4, §5.2):
//! prompts to stderr and answers read from stdin line by line, the sheet as a
//! ruled box on stderr, the dismissal a clear of the screen and its
//! scrollback. THE PERSON DOORS REQUIRE A CONTROLLING TERMINAL and refuse
//! without one (exit 3) — the check is THIS implementation's and never the
//! walk's, so the same walks run under the shell's native windows and the
//! library's scripted person. The realization here is the std streams'
//! `isatty` on BOTH stdin and stderr: a wrapper that captures the one or
//! feeds the other — the wrapper §2.4 names as satisfying every step of the
//! backup moment with no paper and no person — fails it. Each moment is
//! [`moment`]'s, written once against a [`Desk`], where its lines are said
//! and its answers read: the [`Terminal`] is the desk over the std streams,
//! and this module's tests drive the same moments from a script. Every
//! prompt the CLI makes is read through `answer`, those a command that is
//! no person door asks among them, so none reaches stdout. Every line the
//! binary says on stderr — a statement, a prompt's heading, a command's
//! TALK, a halt — is written by `talk`, and a prompt's text and the sheet
//! by `show`, each through `write_inert`, which renders its text INERT
//! ([`inert`], AUTH-5.2's rendering line by line) before stderr is handed
//! a byte: a byte a board, a reply or a file chose — an escape that moves
//! the cursor, erases a line, sets the title or the clipboard, or asks the
//! terminal to type an answer into stdin — reaches the screen as its code
//! point and never as a command. The dismissal's clear, the one escape this
//! binary means, is `clear`'s constant, written raw. Both writers drop a
//! write stderr refuses rather than panic.

use std::fmt;
use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;

use skep_client::person::{Abandoned, Confirmation, Consent, Destination, HandedPath, Import, Imported, KeptOrPlaced, LabelBox, Person, Public, Question, Retype, Retyped, Secret, Sheet, Statement};
use skep_client::sheet::render_inert;

/// The one escape sequence this binary means: the dismissal's clear of the
/// screen and its scrollback (§5.2; §4.2 step 6) — a constant, never a
/// foreign byte.
const CLEAR: &str = "\x1b[2J\x1b[3J\x1b[H";

/// Whether a controlling terminal stands at both ends of a prompt.
pub fn has_terminal() -> bool {
    io::stdin().is_terminal() && io::stderr().is_terminal()
}

/// `text` as the terminal may be handed it: each line rendered INERT by
/// AUTH-5.2's rendering (`render_inert`: every C0 control, DEL and bidi
/// control shown as its code point), the line breaks kept — the one thing a
/// TALK block's own text holds that the rendering would otherwise touch.
/// Rendered twice, the same: the rendering's output holds nothing it
/// renders, so a label a walk rendered already passes as it stands.
fn inert(text: &str) -> String {
    text.split('\n').map(render_inert).collect::<Vec<_>>().join("\n")
}

/// TALK (§2.4): one line on stderr, through [`write_inert`] — a moment's
/// statement or heading, the reason an answer is asked again, a command's
/// talk, a halt's block — the one line writer the binary has. A line stderr
/// refuses is dropped, never a panic, whose exit 101 §2.3 does not have:
/// the exit code, or the answer read next, carries the outcome.
pub fn talk(line: impl fmt::Display) {
    write_inert(&format!("{line}\n"));
}

/// `text` on stderr, through [`write_inert`] — a prompt its answer follows
/// on the same line, the sheet's box.
fn show(text: &str) {
    write_inert(text);
}

/// `text` on stderr rendered [`inert`], flushed — the door every line and
/// prompt passes, so no caller hands stderr a byte the rendering has not
/// seen; dropped where stderr refuses it, never a panic.
fn write_inert(text: &str) {
    let mut err = io::stderr().lock();
    let _ = err.write_all(inert(text).as_bytes()).and_then(|()| err.flush());
}

/// The dismissal's clear on stderr, flushed: [`CLEAR`], the one escape this
/// binary writes and its one write past [`write_inert`] — dropped where
/// stderr refuses it.
fn clear() {
    let mut err = io::stderr().lock();
    let _ = err.write_all(CLEAR.as_bytes()).and_then(|()| err.flush());
}

/// `prompt` on stderr, then one answer read from stdin: the line without its
/// line ending, or `None` at the end of input. The one reader every prompt
/// the CLI makes goes through — `Terminal`'s and `bind`'s alike — locking
/// stdin for that one line alone, so a payload or token read with `-` before
/// or after a prompt never waits on a lock a prompt holds.
pub fn answer(prompt: &str) -> io::Result<Option<String>> {
    show(prompt);
    let mut line = String::new();
    if io::stdin().read_line(&mut line)? == 0 {
        return Ok(None);
    }
    Ok(Some(line.trim_end_matches(['\n', '\r']).to_string()))
}

/// Where a moment says its lines and reads its answers: the terminal's own
/// streams at every door ([`Terminal`]), a script in this module's tests.
trait Desk {
    /// `prompt` shown, then one answer: the line without its line ending, or
    /// the person gone — the end of input, or the input unreadable.
    fn answer(&mut self, prompt: &str) -> Result<String, Abandoned>;
    /// One line said.
    fn talk(&mut self, line: &str);
    /// `text` shown — a prompt's or the sheet's.
    fn show(&mut self, text: &str);
    /// The screen and its scrollback cleared (§5.2; §4.2 step 6).
    fn clear(&mut self);
}

/// The terminal person. It holds nothing: every moment is said on stderr
/// and answered from stdin, through [`talk`], [`show`], [`clear`] and
/// [`answer`].
#[derive(Clone, Copy, Debug, Default)]
pub struct Terminal;

impl Desk for Terminal {
    fn answer(&mut self, prompt: &str) -> Result<String, Abandoned> {
        answer(prompt).ok().flatten().ok_or(Abandoned)
    }

    fn talk(&mut self, line: &str) {
        talk(line);
    }

    fn show(&mut self, text: &str) {
        show(text);
    }

    fn clear(&mut self) {
        clear();
    }
}

/// Each moment is [`moment`]'s, on the terminal's own streams.
impl Person for Terminal {
    fn say(&mut self, m: Public<Statement>) {
        moment::say(self, &m.0);
    }

    fn label(&mut self, m: Public<LabelBox>) -> Result<String, Abandoned> {
        moment::label(self, m.0)
    }

    fn ask(&mut self, m: Public<Question>) -> Result<String, Abandoned> {
        moment::ask(self, &m.0)
    }

    fn yes_no(&mut self, m: Public<Question>) -> Result<bool, Abandoned> {
        moment::yes_no(self, &m.0)
    }

    fn sheet(&mut self, m: Secret<Sheet>) -> Result<(), Abandoned> {
        moment::sheet(self, &m.0)
    }

    fn dismiss(&mut self) {
        moment::dismiss(self);
    }

    fn retype(&mut self, m: Secret<Retype>) -> Result<Retyped, Abandoned> {
        moment::retype(self, &m.0)
    }

    fn destination(&mut self, m: Secret<Destination>) -> Result<PathBuf, Abandoned> {
        moment::destination(self, &m.0)
    }

    fn confirm_typed(&mut self, m: Consent<Confirmation>) -> Result<String, Abandoned> {
        moment::confirm_typed(self, &m.0)
    }

    fn import(&mut self, m: Secret<Import>) -> Result<Imported, Abandoned> {
        moment::import(self, &m.0)
    }

    fn kept_or_placed(&mut self, m: Secret<HandedPath>) -> Result<KeptOrPlaced, Abandoned> {
        moment::kept_or_placed(self, &m.0)
    }
}

/// A path, asked again until one is given; `refusal` says why an empty
/// line is no answer.
fn path_line(desk: &mut impl Desk, prompt: &str, refusal: &str) -> Result<PathBuf, Abandoned> {
    loop {
        let p = desk.answer(prompt)?;
        if !p.trim().is_empty() {
            return Ok(PathBuf::from(p.trim()));
        }
        desk.talk(refusal);
    }
}

/// A seed typed from the print, its whitespace removed — the R42 groups a
/// print shows — and nothing else judged: the walk's `Seed::from_hex`
/// decides it and asks again on a wrong one (AUTH-5.41).
fn seed_line(desk: &mut impl Desk, prompt: &str) -> Result<String, Abandoned> {
    Ok(desk.answer(prompt)?.split_whitespace().collect())
}

/// A fingerprint prefix typed from the print, trimmed — the walk's prefix
/// test decides it (AUTH-5.39).
fn prefix_line(desk: &mut impl Desk) -> Result<String, Abandoned> {
    Ok(desk.answer("fingerprint prefix from the print (at least the first 8 hex): ")?.trim().to_string())
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
/// its width to the sheet's field list, the fields the library's), each line
/// padded to the widest — `fmt`'s width counts chars, as the rule's does.
fn boxed(lines: &[String]) -> String {
    let width = lines.iter().map(|l| l.chars().count()).max().unwrap_or(0).max(20);
    let bar = "─".repeat(width + 2);
    let mut out = format!("┌{bar}┐\n");
    for l in lines {
        out.push_str(&format!("│ {l:<width$} │\n"));
    }
    out.push_str(&format!("└{bar}┘\n"));
    out
}

/// THE MOMENTS, each written once against any [`Desk`]: what a walk's
/// `Person` call says, and how its answer is read — asked again where an
/// answer names none of the moment's choices, and abandoned where the desk
/// answers nothing.
mod moment {
    use std::path::PathBuf;

    use skep_client::person::{Abandoned, Confirmation, Destination, HandedPath, Import, Imported, KeptOrPlaced, LabelBox, Question, Retype, Retyped, Sheet, Statement};

    use super::{arm, boxed, path_line, prefix_line, seed_line, Arm, Desk};

    /// A statement, with the rule it renders.
    pub fn say(desk: &mut impl Desk, s: &Statement) {
        desk.talk(&format!("[{}] {}", s.rule, s.text));
    }

    /// A name box (AUTH-5.42): its title and its statements said, then the
    /// name asked — the default offered, and taken where the answer is
    /// empty. The walk's domain test judges the name (AUTH-1.24).
    pub fn label(desk: &mut impl Desk, b: LabelBox) -> Result<String, Abandoned> {
        desk.talk(&format!("{}:", b.title));
        for s in &b.statements {
            desk.talk(&format!("  {s}"));
        }
        let prompt = match &b.default {
            Some(d) => format!("{} [{d}]: ", b.title),
            None => format!("{}: ", b.title),
        };
        let typed = desk.answer(&prompt)?;
        Ok(if typed.is_empty() { b.default.unwrap_or_default() } else { typed })
    }

    /// A question over public facts: its text the prompt, its answer as
    /// typed.
    pub fn ask(desk: &mut impl Desk, q: &Question) -> Result<String, Abandoned> {
        desk.answer(&q.text)
    }

    /// A yes or a no, asked again until the answer is one.
    pub fn yes_no(desk: &mut impl Desk, q: &Question) -> Result<bool, Abandoned> {
        loop {
            let a = desk.answer(&format!("{} [y/n]: ", q.text))?;
            match a.trim().to_ascii_lowercase().as_str() {
                "y" | "yes" => return Ok(true),
                "n" | "no" => return Ok(false),
                _ => desk.talk("answer y or n"),
            }
        }
    }

    /// The sheet as a ruled box (§5.2), its field list the library's, held
    /// until the person answers that it is printed.
    pub fn sheet(desk: &mut impl Desk, s: &Sheet) -> Result<(), Abandoned> {
        let mut lines = vec!["skep anchor sheet — print this; the seed below is the key".to_string(), String::new()];
        for (name, value) in s.fields.lines() {
            let mut parts = value.lines();
            lines.push(format!("{name:<12}{}", parts.next().unwrap_or("")));
            for rest in parts {
                lines.push(format!("{:<12}{rest}", ""));
            }
        }
        desk.show(&boxed(&lines));
        desk.answer("press return once the sheet is printed: ")?;
        Ok(())
    }

    /// The dismissal: the screen and its scrollback cleared (§5.2; §4.2
    /// step 6).
    pub fn dismiss(desk: &mut impl Desk) {
        desk.clear();
    }

    /// The re-type from the print (AUTH-5.41): the seed, an empty one
    /// declining the re-type with no prefix asked (§4.2 step 9), then the
    /// fingerprint prefix — each passed to the walk, which judges them.
    pub fn retype(desk: &mut impl Desk, r: &Retype) -> Result<Retyped, Abandoned> {
        desk.talk(&r.prompt);
        let seed_hex = seed_line(desk, "seed (64 hex, spaces allowed; empty to decline the re-type): ")?;
        if seed_hex.is_empty() {
            return Ok(Retyped::Declined);
        }
        Ok(Retyped::Typed { seed_hex, fingerprint_prefix: prefix_line(desk)? })
    }

    /// One anchor file's destination: a directory, asked again on an empty
    /// line — no default is offered (§4.2 step 4).
    pub fn destination(desk: &mut impl Desk, d: &Destination) -> Result<PathBuf, Abandoned> {
        desk.talk(&d.prompt);
        path_line(desk, "directory: ", "a directory is required; no default is offered")
    }

    /// A typed confirmation, answered with the text typed, trimmed — never
    /// reduced to a yes or a no, so the walk tells `no` from a wrong row
    /// (AUTH-5.46).
    pub fn confirm_typed(desk: &mut impl Desk, c: &Confirmation) -> Result<String, Abandoned> {
        desk.talk(&c.text);
        let a = desk.answer(&format!("type `{}` to confirm, or `no`: ", c.expected))?;
        Ok(a.trim().to_string())
    }

    /// The import: the ARM is the person's answer, asked first — the kept
    /// FILE, the PRINT, or NEITHER — and never a guess from the text, where
    /// a seed with one character wrong looks like a path. The typed seed
    /// (its whitespace removed) and prefix (trimmed) go to the walk with
    /// nothing else judged: its `Seed::from_hex` and prefix test judge them
    /// and ask again on a wrong one (AUTH-5.39, AUTH-5.41).
    pub fn import(desk: &mut impl Desk, i: &Import) -> Result<Imported, Abandoned> {
        desk.talk(&i.prompt);
        loop {
            match arm(&desk.answer("which do you hold: the kept FILE (f), the PRINT (p), or NEITHER (n)? ")?) {
                Some(Arm::File) => return Ok(Imported::File(path_line(desk, "the file's path: ", "a path is required")?)),
                Some(Arm::Print) => {
                    let seed_hex = seed_line(desk, "the seed's 64 hex from the print (spaces allowed): ")?;
                    return Ok(Imported::Typed { seed_hex, fingerprint_prefix: prefix_line(desk)? });
                }
                Some(Arm::Neither) => return Ok(Imported::Neither),
                None => desk.talk("answer f, p or n"),
            }
        }
    }

    /// Kept or placed (AUTH-5.54 step 3's file arm), asked again until the
    /// answer is one.
    pub fn kept_or_placed(desk: &mut impl Desk, h: &HandedPath) -> Result<KeptOrPlaced, Abandoned> {
        desk.talk(&h.text);
        loop {
            let a = desk.answer(&format!("is {} the KEPT artifact (k) or a PLACED copy (p)? ", h.path.display()))?;
            match a.trim().to_ascii_lowercase().as_str() {
                "k" | "kept" => return Ok(KeptOrPlaced::Kept),
                "p" | "placed" => return Ok(KeptOrPlaced::Placed),
                _ => desk.talk("answer k or p"),
            }
        }
    }
}

#[cfg(test)]
mod tests;
