//! The `Person` seam (`client.md` §1.1's `person` row; §5).
//!
//! The human moments are calls the embedder answers, in three classes the
//! trait marks as types (§9 item 42):
//!
//! * secret moments carry key material — the sheet, the re-type, the anchor
//!   file's destination, the import, kept-or-placed — and the embedder
//!   answers them in its own hands, never a page;
//! * consent moments are public data answered in the shell's own window:
//!   every comparison and confirmation that gates a permanent credential
//!   act, which the surface that issued the act never answers;
//! * public moments carry neither — the statements, the boxes, the display
//!   name, every question over public facts — and may be forwarded.
//!
//! The generic "forward every moment" embedder is unwritable: routing is
//! chosen per class. Nothing inspects the surface — the obligation is named
//! where an embedder must meet it. `dismiss` is a secret moment's close
//! (§4.2 step 6): the exported material is no longer displayed at this
//! surface and not recoverable from it. The walks require a `Person`, never
//! a terminal: the CLI's `Person` checks for one, the shell's sends the
//! public moments to its page and answers the secret and consent ones in its
//! dev arm, and `scripted::Scripted`, behind `test-hooks`, is the seam a
//! test drives.

use std::fmt;
use std::path::PathBuf;

use crate::sheet::SheetFields;

#[cfg(any(test, feature = "test-hooks"))]
pub mod scripted;

/// A public moment's payload: no key material; may be forwarded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Public<T>(pub T);

/// A secret moment's payload: carries, or asks for, key material.
///
/// It therefore prints as `Secret(…)` whatever it holds: an embedder that
/// logs moments with `{:?}` writes no seed into its log.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret<T>(pub T);

impl<T> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(…)")
    }
}

/// A consent moment's payload: public data gating a permanent credential act.
///
/// It is answered in the embedder's own hands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Consent<T>(pub T);

/// A pinned statement, with the rule it renders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Statement {
    /// The rule the statement renders.
    pub rule: &'static str,
    /// The statement's text.
    pub text: String,
}

/// A name box (AUTH-5.42).
///
/// It holds the box's title and statements, and a default where the box
/// offers one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabelBox {
    /// The box's title.
    pub title: String,
    /// The box's statements.
    pub statements: Vec<String>,
    /// The default label, where the box offers one.
    pub default: Option<String>,
}

/// A question over public facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    /// The question's text.
    pub text: String,
}

/// The paper path's sheet (secret).
///
/// It is the field list (AUTH-5.38) with the seed grouped (AUTH-5.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sheet {
    /// The sheet's fields.
    pub fields: SheetFields,
}

/// The re-type from the print (AUTH-5.41: "the 64 hex typed once") — secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Retype {
    /// The prompt shown.
    pub prompt: String,
}

/// The re-type's answer.
///
/// It is the hex and a fingerprint prefix of at least one R42 group (§9
/// item 35), or the re-type declined (§4.2 step 9). Its `Debug` shows the
/// seed as `…`.
#[derive(Clone, PartialEq, Eq)]
pub enum Retyped {
    /// The hex as typed, with a fingerprint prefix.
    Typed { seed_hex: String, fingerprint_prefix: String },
    /// The re-type declined.
    Declined,
}

impl fmt::Debug for Retyped {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Retyped::Typed { fingerprint_prefix, .. } => {
                f.debug_struct("Typed").field("seed_hex", &format_args!("…")).field("fingerprint_prefix", fingerprint_prefix).finish()
            }
            Retyped::Declined => f.write_str("Declined"),
        }
    }
}

/// Where to write one anchor file (§4.2 step 4; §6).
///
/// It is asked for each anchor no `--anchor-out` names, and again after a
/// path inside the store, no default offered — secret, the destination
/// being where key material lands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    /// The prompt shown.
    pub prompt: String,
    /// Which anchor the file is for.
    pub which: usize,
}

/// A typed confirmation gating a permanent act (consent).
///
/// The person types `expected` (the row — a fingerprint's first R42 group —
/// where a row is what the act names, AUTH-5.46) or `no`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Confirmation {
    /// The confirmation's text.
    pub text: String,
    /// The text the person types to confirm.
    pub expected: String,
}

/// The anchor import (`client.md` §4a.2 R1) — secret.
///
/// The artifact is handed in: a file picked from disk, the 64 hex typed
/// from a print with a fingerprint prefix of at least one R42 group (§9
/// item 35), or "I hold neither" — an answer and never an error (AUTH-5.16's
/// no-artifact arm). The moment is asked only where no `--anchor` named the
/// file, so a file is always one of its answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Import {
    /// The prompt shown.
    pub prompt: String,
}

/// The import's answer.
///
/// Its `Debug` shows a typed seed as `…`.
#[derive(Clone, PartialEq, Eq)]
pub enum Imported {
    /// A file picked from disk.
    File(PathBuf),
    /// The hex typed from a print, with a fingerprint prefix.
    Typed { seed_hex: String, fingerprint_prefix: String },
    /// "I hold neither": no artifact to import.
    Neither,
}

impl fmt::Debug for Imported {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Imported::File(path) => f.debug_tuple("File").field(path).finish(),
            Imported::Typed { fingerprint_prefix, .. } => {
                f.debug_struct("Typed").field("seed_hex", &format_args!("…")).field("fingerprint_prefix", fingerprint_prefix).finish()
            }
            Imported::Neither => f.write_str("Neither"),
        }
    }
}

/// The handed path, asked kept or placed — secret.
///
/// The moment is AUTH-5.54 step 3's file arm (`client.md` §4a.2 R1):
/// whether the handed path is the kept artifact (retained) or a placed copy
/// (destroyed when the ceremony ends); "kept-or-placed is not a
/// filesystem-readable property of a path", so the person answers what no
/// read can.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandedPath {
    /// The handed path.
    pub path: PathBuf,
    /// The question's text.
    pub text: String,
}

/// The kept-or-placed answer (AUTH-5.54 step 3's file arm).
///
/// The handed path is the kept artifact, retained, or a placed copy,
/// destroyed when the ceremony ends (`client.md` §4a.2 R1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeptOrPlaced {
    /// The kept artifact, retained.
    Kept,
    /// A placed copy, destroyed when the ceremony ends.
    Placed,
}

/// The person left: an EOF, a Ctrl-C, a window closed.
///
/// The walk takes its own abandonment exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Abandoned;

impl fmt::Display for Abandoned {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the person abandoned the walk")
    }
}

impl std::error::Error for Abandoned {}

/// The seam.
pub trait Person {
    /// Says a statement (public).
    fn say(&mut self, m: Public<Statement>);
    /// Answers a name box (public).
    ///
    /// The box's own domain test is the walk's, which re-asks on a refusal.
    ///
    /// # Errors
    ///
    /// [`Abandoned`] where the person leaves.
    fn label(&mut self, m: Public<LabelBox>) -> Result<String, Abandoned>;
    /// Answers a question over public facts in text (public).
    ///
    /// # Errors
    ///
    /// [`Abandoned`] where the person leaves.
    fn ask(&mut self, m: Public<Question>) -> Result<String, Abandoned>;
    /// Answers a yes-or-no question over public facts (public).
    ///
    /// # Errors
    ///
    /// [`Abandoned`] where the person leaves.
    fn yes_no(&mut self, m: Public<Question>) -> Result<bool, Abandoned>;
    /// Displays the sheet (secret).
    ///
    /// # Errors
    ///
    /// [`Abandoned`] where the person leaves.
    fn sheet(&mut self, m: Secret<Sheet>) -> Result<(), Abandoned>;
    /// Closes the secret moment (§4.2 step 6).
    ///
    /// Whatever was displayed is no longer, at this surface, and not
    /// recoverable from it.
    fn dismiss(&mut self);
    /// Asks the re-type from the print (secret).
    ///
    /// # Errors
    ///
    /// [`Abandoned`] where the person leaves.
    fn retype(&mut self, m: Secret<Retype>) -> Result<Retyped, Abandoned>;
    /// Asks one anchor file's destination (secret).
    ///
    /// # Errors
    ///
    /// [`Abandoned`] where the person leaves.
    fn destination(&mut self, m: Secret<Destination>) -> Result<PathBuf, Abandoned>;
    /// Asks a typed confirmation (consent).
    ///
    /// It is answered with the text the person typed, verbatim — never
    /// reduced to a yes or a no, so a walk tells `no` from a wrong row and
    /// re-asks the row (AUTH-5.46: "the wrong row is the mistake stress
    /// produces"). The one confirmation any walk asks.
    ///
    /// # Errors
    ///
    /// [`Abandoned`] where the person leaves.
    fn confirm_typed(&mut self, m: Consent<Confirmation>) -> Result<String, Abandoned>;
    /// Asks the anchor import (secret): a file, the typed hex, or neither.
    ///
    /// # Errors
    ///
    /// [`Abandoned`] where the person leaves.
    fn import(&mut self, m: Secret<Import>) -> Result<Imported, Abandoned>;
    /// Asks whether the handed path is kept or placed (secret).
    ///
    /// It is the bridge's `keptOrPlaced` (`client.md` §4b.3).
    ///
    /// # Errors
    ///
    /// [`Abandoned`] where the person leaves.
    fn kept_or_placed(&mut self, m: Secret<HandedPath>) -> Result<KeptOrPlaced, Abandoned>;
}

#[cfg(test)]
mod tests {
    use super::scripted::{Script, Scripted};
    use super::*;

    /// The scripted seam answers in order and records every moment's class.
    ///
    /// It abandons where the script says.
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
        let left: Box<dyn std::error::Error> = Box::new(Abandoned);
        assert_eq!(left.to_string(), "the person abandoned the walk", "an embedder's `?` carries it");
    }

    /// The secret class prints no key material.
    ///
    /// The marker prints as `Secret(…)` whatever it holds, and a typed seed
    /// shows as `…` beside its public prefix.
    #[test]
    fn a_secret_moment_prints_no_seed() {
        let seed_hex = "5e".repeat(32);
        let retyped = Retyped::Typed { seed_hex: seed_hex.clone(), fingerprint_prefix: "0123abcd".into() };
        let imported = Imported::Typed { seed_hex: seed_hex.clone(), fingerprint_prefix: "0123abcd".into() };
        for printed in [format!("{:?}", Secret(retyped.clone())), format!("{retyped:?}"), format!("{imported:?}"), format!("{:?}", Secret(Retype { prompt: "type the seed".into() }))] {
            assert!(!printed.contains("5e5e5e5e"), "{printed}");
        }
        assert_eq!(format!("{:?}", Secret(imported)), "Secret(…)");
        assert!(format!("{retyped:?}").contains("0123abcd"));
    }
}
