//! The CLI's `Person` over the terminal (`client.md` §1.2, §2.4, §5.2).
//!
//! It shows prompts on stderr and reads answers from stdin line by line,
//! the sheet as a ruled box on stderr, the dismissal a clear of the screen
//! and its scrollback. The person doors require a controlling terminal and
//! refuse without one (exit 3) — the check is this implementation's and
//! never the walk's, so the same walks run under the shell's native
//! windows and the library's scripted person. The realization here is the
//! std streams' `isatty` on both stdin and stderr: a wrapper that captures
//! the one or feeds the other — the wrapper §2.4 names as satisfying every
//! step of the backup moment with no paper and no person — fails it. Each
//! moment is [`moment`]'s, written once against a [`Screen`], where its
//! lines are said and its answers read: the [`Terminal`] is the screen over
//! the std streams, and this module's tests drive the same moments from a
//! script. Every prompt the CLI makes is read through `answer`, those a
//! command that is no person door asks among them, so none reaches stdout.
//! Every line the binary says on stderr — a statement, a prompt's heading,
//! a command's talk, a halt — is written by `talk`, and a prompt's text and
//! the sheet by `show`, each through `write_inert`, which renders its text
//! inert ([`inert`], AUTH-5.2's rendering line by line: every control
//! character, C0, DEL and C1, and every bidi control) before stderr is
//! handed a byte: a control a board, a reply or a file chose — an escape,
//! 7-bit or 8-bit, that moves the cursor, erases a line, sets the title or
//! the clipboard, or asks the terminal to type an answer into stdin —
//! reaches the screen as its code point and never as a command. The
//! dismissal's clear, the one escape this binary means, is `clear`'s
//! constant, written raw. Both writers drop a write stderr refuses rather
//! than panic.

use std::fmt;
use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;

use skep_client::person::{Abandoned, Confirmation, Consent, Destination, HandedPath, Import, Imported, KeptOrPlaced, LabelBox, Person, Public, Question, Retype, Retyped, Secret, Sheet, Statement};
use skep_client::sheet::render_inert;

/// The one escape sequence this binary means: the dismissal's clear.
///
/// It clears the screen and its scrollback (§5.2; §4.2 step 6) — a
/// constant, never a foreign byte.
const CLEAR: &str = "\x1b[2J\x1b[3J\x1b[H";

/// Returns whether a controlling terminal stands at both ends of a prompt.
pub fn has_terminal() -> bool {
    io::stdin().is_terminal() && io::stderr().is_terminal()
}

/// Returns `text` as the terminal may be handed it, each line rendered inert.
///
/// Every character AUTH-5.2 names — a control character (C0, DEL and C1)
/// or a bidi control — is shown as its code point: `render_inert`'s
/// rendering, and the C1 controls its set leaves out spelled as it spells
/// the rest. The line breaks are kept, the one thing a talk block's own
/// text holds that the rendering would otherwise touch. Rendered twice, the
/// same: the rendering's output holds nothing it renders, so a label a walk
/// rendered already passes as it stands.
fn inert(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for (i, line) in text.split('\n').enumerate() {
        if i > 0 {
            out.push('\n');
        }
        // What `render_inert` leaves of the control characters: C1.
        for c in render_inert(line).chars() {
            if c.is_control() {
                out.push_str(&format!("<U+{:04X}>", u32::from(c)));
            } else {
                out.push(c);
            }
        }
    }
    out
}

/// Writes one line of talk (§2.4) on stderr, through [`write_inert`].
///
/// The line is a moment's statement or heading, the reason an answer is
/// asked again, a command's talk, a halt's block — this is the one line
/// writer the binary has. A line stderr refuses is dropped, never a panic,
/// whose exit 101 §2.3 does not have: the exit code, or the answer read
/// next, carries the outcome.
pub fn talk(line: impl fmt::Display) {
    write_inert(&format!("{line}\n"));
}

/// Writes `text` on stderr, through [`write_inert`].
///
/// It is a prompt its answer follows on the same line, or the sheet's box.
fn show(text: &str) {
    write_inert(text);
}

/// Writes `text` on stderr rendered [`inert`], flushed.
///
/// It is the door every line and prompt passes, so no caller hands stderr a
/// byte the rendering has not seen; a write stderr refuses is dropped,
/// never a panic.
fn write_inert(text: &str) {
    let mut err = io::stderr().lock();
    let _ = err.write_all(inert(text).as_bytes()).and_then(|()| err.flush());
}

/// Writes the dismissal's clear on stderr, flushed.
///
/// It is [`CLEAR`], the one escape this binary writes and its one write past
/// [`write_inert`] — dropped where stderr refuses it.
fn clear() {
    let mut err = io::stderr().lock();
    let _ = err.write_all(CLEAR.as_bytes()).and_then(|()| err.flush());
}

/// Shows `prompt` on stderr, then reads one answer from stdin.
///
/// The answer is the line without its line ending, or `None` at the end of
/// input. This is the one reader every prompt the CLI makes goes through —
/// `Terminal`'s and `bind`'s alike — locking stdin for that one line alone,
/// so a payload or token read with `-` before or after a prompt never waits
/// on a lock a prompt holds.
///
/// # Errors
///
/// Returns the I/O error stdin's read meets, a line that is not UTF-8 text
/// among them.
pub fn answer(prompt: &str) -> io::Result<Option<String>> {
    show(prompt);
    let mut line = String::new();
    if io::stdin().read_line(&mut line)? == 0 {
        return Ok(None);
    }
    Ok(Some(line.trim_end_matches(['\n', '\r']).to_string()))
}

/// The screen a moment says its lines on and reads its answers from.
///
/// It is the terminal's own streams at every door ([`Terminal`]), a script
/// in this module's tests.
trait Screen {
    /// Shows `prompt`, then answers the line without its line ending.
    ///
    /// # Errors
    ///
    /// Returns [`Abandoned`] where the person is gone — the end of input, or
    /// the input unreadable, said on stderr where it is: an answer abandoned
    /// for a byte the terminal sent is no person who left.
    fn answer(&mut self, prompt: &str) -> Result<String, Abandoned>;
    /// Says one line.
    fn talk(&mut self, line: &str);
    /// Shows `text`, a prompt's or the sheet's.
    fn show(&mut self, text: &str);
    /// Clears the screen and its scrollback (§5.2; §4.2 step 6).
    fn clear(&mut self);
}

/// The terminal person.
///
/// It holds nothing: every moment is said on stderr and answered from
/// stdin, through [`talk`], [`show`], [`clear`] and [`answer`].
#[derive(Clone, Copy, Debug, Default)]
pub struct Terminal;

impl Screen for Terminal {
    /// Shows `prompt` and reads one answer through [`answer`].
    ///
    /// # Errors
    ///
    /// Returns [`Abandoned`] at the end of input — the person gone, said by
    /// the walk — and where stdin could not read the answer: a line that is
    /// not UTF-8 text, typed at a terminal in another encoding or pasted,
    /// abandons the moment too, and its cause is said here, where the walk
    /// would say only "abandoned".
    fn answer(&mut self, prompt: &str) -> Result<String, Abandoned> {
        match answer(prompt) {
            Ok(Some(line)) => Ok(line),
            Ok(None) => Err(Abandoned),
            Err(e) => {
                talk(format!("the answer could not be read from stdin ({e}): this moment is abandoned"));
                Err(Abandoned)
            }
        }
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

/// Returns a path, asked again until one is given.
///
/// `refusal` says why an empty line is no answer.
///
/// # Errors
///
/// Returns [`Abandoned`] where the screen answers nothing.
fn path_line(screen: &mut impl Screen, prompt: &str, refusal: &str) -> Result<PathBuf, Abandoned> {
    loop {
        let p = screen.answer(prompt)?;
        if !p.trim().is_empty() {
            return Ok(PathBuf::from(p.trim()));
        }
        screen.talk(refusal);
    }
}

/// Returns a seed typed from the print, its whitespace removed.
///
/// The whitespace is the R42 groups a print shows, and nothing else is
/// judged: the walk's `Seed::from_hex` decides the seed and asks again on a
/// wrong one (AUTH-5.41).
///
/// # Errors
///
/// Returns [`Abandoned`] where the screen answers nothing.
fn seed_line(screen: &mut impl Screen, prompt: &str) -> Result<String, Abandoned> {
    Ok(screen.answer(prompt)?.split_whitespace().collect())
}

/// Returns a fingerprint prefix typed from the print, trimmed.
///
/// The walk's prefix test decides it (AUTH-5.39).
///
/// # Errors
///
/// Returns [`Abandoned`] where the screen answers nothing.
fn prefix_line(screen: &mut impl Screen) -> Result<String, Abandoned> {
    Ok(screen.answer("fingerprint prefix from the print (at least the first 8 hex): ")?.trim().to_string())
}

/// The anchor import's three arms: what the person holds.
///
/// They are `client.md` §4a.2 R1's.
#[derive(Debug, PartialEq, Eq)]
enum Arm {
    File,
    Print,
    Neither,
}

/// Returns the arm an answer names — `f`, `p` or `n`, or the word.
///
/// It is `None` else, and asked again: a path or a seed given here names no
/// arm, so neither is ever routed by its look.
fn arm(text: &str) -> Option<Arm> {
    match text.trim().to_ascii_lowercase().as_str() {
        "f" | "file" => Some(Arm::File),
        "p" | "print" => Some(Arm::Print),
        "n" | "neither" => Some(Arm::Neither),
        _ => None,
    }
}

/// Returns the ruled box around `lines` that stderr shows.
///
/// The terminal adds the box and its width to the sheet's field list, the
/// fields the library's (§5.2). Each line is padded to the widest — `fmt`'s
/// width counts chars, as the rule's does.
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

/// The moments, each written once against any [`Screen`].
///
/// A moment is what a walk's `Person` call says, and how its answer is read
/// — asked again where an answer names none of the moment's choices, and
/// abandoned where the screen answers nothing.
mod moment {
    use std::path::PathBuf;

    use skep_client::person::{Abandoned, Confirmation, Destination, HandedPath, Import, Imported, KeptOrPlaced, LabelBox, Question, Retype, Retyped, Sheet, Statement};

    use super::{arm, boxed, path_line, prefix_line, seed_line, Arm, Screen};

    /// Says a statement, with the rule it renders.
    pub fn say(screen: &mut impl Screen, s: &Statement) {
        screen.talk(&format!("[{}] {}", s.rule, s.text));
    }

    /// Asks a name box (AUTH-5.42), its title and its statements said first.
    ///
    /// The name is asked with the default offered, taken where the answer
    /// is empty. The walk's domain test judges the name (AUTH-1.24).
    ///
    /// # Errors
    ///
    /// Returns [`Abandoned`] where the screen answers nothing.
    pub fn label(screen: &mut impl Screen, b: LabelBox) -> Result<String, Abandoned> {
        screen.talk(&format!("{}:", b.title));
        for s in &b.statements {
            screen.talk(&format!("  {s}"));
        }
        let prompt = match &b.default {
            Some(d) => format!("{} [{d}]: ", b.title),
            None => format!("{}: ", b.title),
        };
        let typed = screen.answer(&prompt)?;
        Ok(if typed.is_empty() { b.default.unwrap_or_default() } else { typed })
    }

    /// Asks a question over public facts, its text the prompt.
    ///
    /// Its answer is as typed.
    ///
    /// # Errors
    ///
    /// Returns [`Abandoned`] where the screen answers nothing.
    pub fn ask(screen: &mut impl Screen, q: &Question) -> Result<String, Abandoned> {
        screen.answer(&q.text)
    }

    /// Asks for a yes or a no, again until the answer is one.
    ///
    /// # Errors
    ///
    /// Returns [`Abandoned`] where the screen answers nothing.
    pub fn yes_no(screen: &mut impl Screen, q: &Question) -> Result<bool, Abandoned> {
        loop {
            let a = screen.answer(&format!("{} [y/n]: ", q.text))?;
            match a.trim().to_ascii_lowercase().as_str() {
                "y" | "yes" => return Ok(true),
                "n" | "no" => return Ok(false),
                _ => screen.talk("answer y or n"),
            }
        }
    }

    /// Shows the sheet as a ruled box (§5.2), its field list the library's.
    ///
    /// It is held until the person answers that it is printed.
    ///
    /// # Errors
    ///
    /// Returns [`Abandoned`] where the screen answers nothing.
    pub fn sheet(screen: &mut impl Screen, s: &Sheet) -> Result<(), Abandoned> {
        let mut lines = vec!["skep anchor sheet — print this; the seed below is the key".to_string(), String::new()];
        for (name, value) in s.fields.lines() {
            let mut parts = value.lines();
            lines.push(format!("{name:<12}{}", parts.next().unwrap_or("")));
            for rest in parts {
                lines.push(format!("{:<12}{rest}", ""));
            }
        }
        screen.show(&boxed(&lines));
        screen.answer("press return once the sheet is printed: ")?;
        Ok(())
    }

    /// Clears the screen and its scrollback: the dismissal (§5.2; §4.2 step 6).
    pub fn dismiss(screen: &mut impl Screen) {
        screen.clear();
    }

    /// Asks the re-type from the print (AUTH-5.41): the seed, then the prefix.
    ///
    /// An empty seed declines the re-type with no prefix asked (§4.2 step
    /// 9); the seed and the fingerprint prefix are each passed to the walk,
    /// which judges them.
    ///
    /// # Errors
    ///
    /// Returns [`Abandoned`] where the screen answers nothing.
    pub fn retype(screen: &mut impl Screen, r: &Retype) -> Result<Retyped, Abandoned> {
        screen.talk(&r.prompt);
        let seed_hex = seed_line(screen, "seed (64 hex, spaces allowed; empty to decline the re-type): ")?;
        if seed_hex.is_empty() {
            return Ok(Retyped::Declined);
        }
        Ok(Retyped::Typed { seed_hex, fingerprint_prefix: prefix_line(screen)? })
    }

    /// Asks one anchor file's destination: a directory.
    ///
    /// It is asked again on an empty line — no default is offered (§4.2
    /// step 4).
    ///
    /// # Errors
    ///
    /// Returns [`Abandoned`] where the screen answers nothing.
    pub fn destination(screen: &mut impl Screen, d: &Destination) -> Result<PathBuf, Abandoned> {
        screen.talk(&d.prompt);
        path_line(screen, "directory: ", "a directory is required; no default is offered")
    }

    /// Asks a typed confirmation, answered with the text typed, trimmed.
    ///
    /// It is never reduced to a yes or a no, so the walk tells `no` from a
    /// wrong row (AUTH-5.46).
    ///
    /// # Errors
    ///
    /// Returns [`Abandoned`] where the screen answers nothing.
    pub fn confirm_typed(screen: &mut impl Screen, c: &Confirmation) -> Result<String, Abandoned> {
        screen.talk(&c.text);
        let a = screen.answer(&format!("type `{}` to confirm, or `no`: ", c.expected))?;
        Ok(a.trim().to_string())
    }

    /// Asks the import, the arm first: the kept file, the print, or neither.
    ///
    /// The arm is the person's answer, never a guess from the text, where a
    /// seed with one character wrong looks like a path. The typed seed (its
    /// whitespace removed) and prefix (trimmed) go to the walk with nothing
    /// else judged: its `Seed::from_hex` and prefix test judge them and ask
    /// again on a wrong one (AUTH-5.39, AUTH-5.41).
    ///
    /// # Errors
    ///
    /// Returns [`Abandoned`] where the screen answers nothing.
    pub fn import(screen: &mut impl Screen, i: &Import) -> Result<Imported, Abandoned> {
        screen.talk(&i.prompt);
        loop {
            match arm(&screen.answer("which do you hold: the kept FILE (f), the PRINT (p), or NEITHER (n)? ")?) {
                Some(Arm::File) => return Ok(Imported::File(path_line(screen, "the file's path: ", "a path is required")?)),
                Some(Arm::Print) => {
                    let seed_hex = seed_line(screen, "the seed's 64 hex from the print (spaces allowed): ")?;
                    return Ok(Imported::Typed { seed_hex, fingerprint_prefix: prefix_line(screen)? });
                }
                Some(Arm::Neither) => return Ok(Imported::Neither),
                None => screen.talk("answer f, p or n"),
            }
        }
    }

    /// Asks kept or placed (AUTH-5.54 step 3's file arm).
    ///
    /// It is asked again until the answer is one.
    ///
    /// # Errors
    ///
    /// Returns [`Abandoned`] where the screen answers nothing.
    pub fn kept_or_placed(screen: &mut impl Screen, h: &HandedPath) -> Result<KeptOrPlaced, Abandoned> {
        screen.talk(&h.text);
        loop {
            let a = screen.answer(&format!("is {} the KEPT artifact (k) or a PLACED copy (p)? ", h.path.display()))?;
            match a.trim().to_ascii_lowercase().as_str() {
                "k" | "kept" => return Ok(KeptOrPlaced::Kept),
                "p" | "placed" => return Ok(KeptOrPlaced::Placed),
                _ => screen.talk("answer k or p"),
            }
        }
    }
}

#[cfg(test)]
mod tests;
