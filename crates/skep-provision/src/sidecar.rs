//! THE SIDECAR's ANSWER (step 4, the dark claim): `skep claim --hosted -`'s
//! DATA on stdout and its exit code, read for what they are and nothing
//! this program imagines (the provisioning record §2.3). Its stderr is the
//! operator's TALK — the H0 warnings, each entry's fingerprint, the
//! anchorless line, "the genesis stands" — kept whole in the log and parsed
//! never.
//!
//! THE DATA LINES, one per line through the binary's `data`, every C0
//! control in a value rendered as its code point (`<U+000A>` for a line
//! break), so a byte a board chose forges no second line:
//!
//! 1. `claimant 1.0.1` — the account that claimed the board;
//! 2. `account 1.0.1` and 3. `principal 1` — two of the three facts;
//! 4. `origin http://127.0.0.1:8642` — THE DIALED ORIGIN, the claim run's
//!    loopback the sidecar was told to dial ([`DIALED_ORIGIN`]): asserted
//!    here and shown nowhere — the reply relays the public origin
//!    (AUTH-4.57 (b));
//! 5. `first act: …` and 6. `second act: …` — checked by their prefixes
//!    alone: line 5 embeds the dialed origin and line 6 a literal
//!    `<origin>`, so neither is shown to a person as printed; the reply
//!    composes both again with the public origin (`reply`).
//!
//! EXACTLY those six lines, each value the one this program expects of a
//! fresh alpha board ([`ACCOUNT`], [`PRINCIPAL`], [`DIALED_ORIGIN`]), are
//! [`Answer::Claimed`]; the ONE line `claimed by <claimant>` is
//! [`Answer::AlreadyClaimed`] — the walk's idempotent answer, which on a
//! volume the flow just made is residue and a failed step; any other shape
//! under exit 0 is [`Failure::Shape`]. The exit codes (`skep-client`'s
//! `Halt::exit_code`; `skep-cli`'s `finish`): 0; 2 a usage refusal; 3 HALT
//! AND SURFACE, the topology's one halt among them; 1 the board refused; 4
//! transport — the daemon not yet listening, which the flow retries.

use std::fmt;

use crate::docker::DIALED_ORIGIN;
use crate::process::Exit;

/// The account the dark claim founds on a fresh board — the alpha's
/// claimant under the root `1` — and the address fact the reply carries.
pub const ACCOUNT: &str = "1.0.1";

/// The principal the dark claim binds: `skep claim --hosted`'s default, 1.
pub const PRINCIPAL: u64 = 1;

/// The six DATA lines, read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claimed {
    /// Line 1's value: the claimant.
    pub claimant: String,
    /// Line 2's value: the account founded.
    pub account: String,
    /// Line 3's value: its principal.
    pub principal: String,
    /// Line 4's value: THE DIALED ORIGIN, held to [`DIALED_ORIGIN`] — the one
    /// the sidecar was told to dial — and shown nowhere.
    pub origin: String,
    /// Line 5, whole.
    pub first_act: String,
    /// Line 6, whole.
    pub second_act: String,
}

/// What an exit-0 stdout says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// The six lines: the board claimed now.
    Claimed(Claimed),
    /// The one line `claimed by <claimant>`: the board was claimed before.
    AlreadyClaimed {
        /// The claimant the line names.
        claimant: String,
    },
}

/// Why the sidecar's answer is no claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// Exit 2: a usage refusal — the argv was wrong.
    Usage,
    /// Exit 3: HALT AND SURFACE — the bare bind refused, residue, the
    /// payload's or the preview face, a refused delegate or mint.
    Halt,
    /// Exit 1: the board refused the claim.
    Refused,
    /// Exit 4: transport — the daemon not yet listening, or gone.
    Transport,
    /// Any other exit code, or `None` for an end by signal.
    Exit(Option<i32>),
    /// Exit 0 and a stdout that is neither the six lines nor the one; the
    /// words say which line, never what it held.
    Shape(String),
}

/// The failure as the log says it.
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Failure::Usage => f.write_str("exit 2 (a usage refusal)"),
            Failure::Halt => f.write_str("exit 3 (a halt)"),
            Failure::Refused => f.write_str("exit 1 (the board refused)"),
            Failure::Transport => f.write_str("exit 4 (transport)"),
            Failure::Exit(Some(code)) => write!(f, "exit {code}"),
            Failure::Exit(None) => f.write_str("ended by a signal"),
            Failure::Shape(why) => write!(f, "exit 0 and {why}"),
        }
    }
}

impl std::error::Error for Failure {}

/// THE READ: the exit code mapped, and an exit-0 stdout held to the six
/// lines or the one.
pub fn read(exit: &Exit) -> Result<Answer, Failure> {
    match exit.code {
        Some(0) => {}
        Some(2) => return Err(Failure::Usage),
        Some(3) => return Err(Failure::Halt),
        Some(1) => return Err(Failure::Refused),
        Some(4) => return Err(Failure::Transport),
        other => return Err(Failure::Exit(other)),
    }
    let text = std::str::from_utf8(&exit.stdout).map_err(|_| Failure::Shape("a stdout that is not text".to_owned()))?;
    // One DATA line per `\n`: the sidecar renders every C0 control inside a
    // value as its code point, so a `\n` here is a line's end and nothing
    // else, and `<U+000A>` inside a value is text.
    let lines: Vec<&str> = text.strip_suffix('\n').unwrap_or(text).split('\n').collect();
    match lines.as_slice() {
        [one] if one.starts_with("claimed by ") => Ok(Answer::AlreadyClaimed { claimant: one["claimed by ".len()..].to_owned() }),
        [l1, l2, l3, l4, l5, l6] => {
            let claimant = value(l1, "claimant ", 1)?;
            let account = value(l2, "account ", 2)?;
            let principal = value(l3, "principal ", 3)?;
            let origin = value(l4, "origin ", 4)?;
            if claimant != ACCOUNT || account != ACCOUNT {
                return Err(Failure::Shape(format!("lines 1 and 2 name another account than {ACCOUNT}")));
            }
            if principal != PRINCIPAL.to_string() {
                return Err(Failure::Shape(format!("line 3 names another principal than {PRINCIPAL}")));
            }
            if origin != DIALED_ORIGIN {
                return Err(Failure::Shape(format!("line 4 names another origin than the one dialed, {DIALED_ORIGIN}")));
            }
            if !l5.starts_with("first act: ") {
                return Err(Failure::Shape("line 5 is not the first act".to_owned()));
            }
            if !l6.starts_with("second act: ") {
                return Err(Failure::Shape("line 6 is not the second act".to_owned()));
            }
            Ok(Answer::Claimed(Claimed {
                claimant: claimant.to_owned(),
                account: account.to_owned(),
                principal: principal.to_owned(),
                origin: origin.to_owned(),
                first_act: (*l5).to_owned(),
                second_act: (*l6).to_owned(),
            }))
        }
        other => Err(Failure::Shape(format!("{} lines, neither the six of a claim nor the one of a claimed board", other.len()))),
    }
}

/// Line `at`'s value after its `key`, or the shape refused naming the line.
fn value<'a>(line: &'a str, key: &str, at: usize) -> Result<&'a str, Failure> {
    line.strip_prefix(key).ok_or_else(|| Failure::Shape(format!("line {at} is not `{}…`", key.trim_end())))
}

#[cfg(test)]
mod tests;
