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
//! native windows, and `scripted::Scripted`, behind `test-hooks`, is the
//! seam a test drives.

use std::fmt;
use std::path::PathBuf;

use crate::sheet::SheetFields;

#[cfg(any(test, feature = "test-hooks"))]
pub mod scripted;

/// A PUBLIC moment's payload: no key material; may be forwarded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Public<T>(pub T);

/// A SECRET moment's payload: carries, or asks for, key material — and so
/// prints as `Secret(…)` whatever it holds: an embedder that logs moments
/// with `{:?}` writes no seed into its log.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret<T>(pub T);

impl<T> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(…)")
    }
}

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

/// A name box (AUTH-5.42): the box's statements, and a default where the box
/// offers one.
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
/// R42 group (§9 item 35), or the re-type DECLINED (§4.2 step 9). Its
/// `Debug` shows the seed as `…`.
#[derive(Clone, PartialEq, Eq)]
pub enum Retyped {
    Typed { seed_hex: String, fingerprint_prefix: String },
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
/// The moment is asked only where no `--anchor` named the file, so a file is
/// always one of its answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Import {
    pub prompt: String,
}

/// The import's answer. Its `Debug` shows a typed seed as `…`.
#[derive(Clone, PartialEq, Eq)]
pub enum Imported {
    File(PathBuf),
    Typed { seed_hex: String, fingerprint_prefix: String },
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

/// THE HANDED PATH, asked KEPT OR PLACED (AUTH-5.54 step 3's file arm;
/// `client.md` §4a.2 R1) — SECRET: whether the handed path is the KEPT
/// artifact (retained) or a PLACED copy (destroyed when the ceremony ends);
/// "kept-or-placed is not a filesystem-readable property of a path", so the
/// person answers what no read can.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandedPath {
    pub path: PathBuf,
    pub text: String,
}

/// The kept-or-placed answer (AUTH-5.54 step 3's file arm; `client.md`
/// §4a.2 R1): the handed path is the KEPT artifact, retained, or a PLACED
/// copy, destroyed when the ceremony ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeptOrPlaced {
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
    /// A typed confirmation (CONSENT), answered with THE TEXT THE PERSON
    /// TYPED, verbatim — never reduced to a yes or a no, so a walk tells `no`
    /// from a wrong row and re-asks the row (AUTH-5.46: "the wrong row is the
    /// mistake stress produces"). The one confirmation every walk asks.
    fn confirm_typed(&mut self, m: Consent<Confirmation>) -> Result<String, Abandoned>;
    /// THE ANCHOR IMPORT (SECRET): a file, the typed hex, or neither.
    fn import(&mut self, m: Secret<Import>) -> Result<Imported, Abandoned>;
    /// KEPT OR PLACED (SECRET): the handed path's kept-or-placed answer —
    /// the bridge's `keptOrPlaced` (`client.md` §4b.3).
    fn kept_or_placed(&mut self, m: Secret<HandedPath>) -> Result<KeptOrPlaced, Abandoned>;
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

    /// The SECRET class prints no key material: the marker prints as
    /// `Secret(…)` whatever it holds, and a typed seed shows as `…` beside
    /// its public prefix.
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
