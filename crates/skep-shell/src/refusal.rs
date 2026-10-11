//! THE ONE REFUSAL SHAPE the page renders (`client.md` §4b.1's refusal
//! column: "the armed set; anything else is a `Halt {state, cause, act}` the
//! page renders"): every refusal a call answers is one value with a `kind`
//! and ONE `name` token the page faces on — never prose —
//!
//! * `refused` — the board's own verdict, carried back VERBATIM: the
//!   `rejected` document's code and detail, or a non-200's error, its `name`
//!   the one token `Rejection::key` dispatches on;
//! * `halt` — a halt's face, the state, its cause and the one act, its
//!   `name` the armed refusal the row spells where the shell diagnosed one
//!   (`no_key`, `origin_state`, `retired`, `not_enrolled`, `busy`, …) and
//!   `halt` where the row arms none;
//! * `blocked` — the handshake's `403 prefix_blocked` with its record and
//!   the ground read as a guest;
//! * `unreachable` — the board is not answering;
//! * `shell` — the shell's own refusal: a stale reference (`session_ended`),
//!   a foreign board reference (`unknown_board`), the query bound
//!   (`query_too_long`), a write in the guest form, a call's arguments not
//!   of the row's shape, or a row the library does not reach at this pin
//!   (`not_reached`), each with its detail.

use std::fmt;

use serde_json::{json, Map, Value};
use skep_client::halt::{Blocked, Face, Halt, Refused};
use skep_client::DialError;

/// The refusal.
#[derive(Debug, Clone, PartialEq)]
pub enum Refusal {
    /// The board's own verdict, verbatim.
    Board(Refused),
    /// A halt's face, under the armed name the row spells where one does.
    Halt { name: &'static str, face: Face },
    /// The block.
    Blocked(Blocked),
    /// The board is not answering.
    Unreachable(DialError),
    /// The shell's own refusal.
    Shell { name: &'static str, detail: Value },
}

/// THE PIN's stale-reference refusal: "session ended".
pub const SESSION_ENDED: &str = "session_ended";
/// A board reference this shell instance never issued.
pub const UNKNOWN_BOARD: &str = "unknown_board";
/// A call's arguments are not the row's shape.
pub const MALFORMED_ARGS: &str = "malformed_args";
/// A row the library does not reach at this pin: the detail says where it
/// stops.
pub const NOT_REACHED: &str = "not_reached";
/// A WRITE frame in the guest form, refused without a dial.
pub const WRITE_IN_GUEST_FORM: &str = "write_in_guest_form";
/// The walk was abandoned: the page cancelled a moment.
pub const ABANDONED: &str = "abandoned";

impl Refusal {
    /// The shell's own refusal named `name`, with its detail object.
    pub fn shell(name: &'static str, detail: Value) -> Refusal {
        Refusal::Shell { name, detail }
    }

    /// The row's arguments are not its shape: `what` says which member.
    pub fn malformed(what: impl Into<String>) -> Refusal {
        Refusal::shell(MALFORMED_ARGS, json!({"what": what.into()}))
    }

    /// A halt the row arms no name for.
    pub fn halt(face: Face) -> Refusal {
        Refusal::Halt { name: "halt", face }
    }

    /// A halt under the armed name the row spells.
    pub fn named(name: &'static str, face: Face) -> Refusal {
        Refusal::Halt { name, face }
    }

    /// The family's member as the row carries it: the board's verdict
    /// verbatim, a halt's face, the block, the unreachable board.
    pub fn of(h: Halt) -> Refusal {
        match h {
            Halt::Refused(r) => Refusal::Board(r),
            Halt::Halt(face) => Refusal::halt(face),
            Halt::Blocked(b) => Refusal::Blocked(b),
            Halt::Dial(d) => Refusal::Unreachable(d),
        }
    }

    /// [`Refusal::of`], a halt's face taking `name`.
    pub fn of_named(name: &'static str, h: Halt) -> Refusal {
        match h {
            Halt::Halt(face) => Refusal::Halt { name, face },
            other => Refusal::of(other),
        }
    }

    /// The one token the page faces on.
    pub fn name(&self) -> String {
        match self {
            Refusal::Board(r) => match (r.code.as_str(), r.detail.as_deref()) {
                ("credential_refused" | "registry_refused", Some(d)) => d.to_string(),
                (code, _) => code.to_string(),
            },
            Refusal::Halt { name, .. } => (*name).to_string(),
            Refusal::Blocked(_) => "blocked".to_string(),
            Refusal::Unreachable(_) => "unreachable".to_string(),
            Refusal::Shell { name, .. } => (*name).to_string(),
        }
    }

    /// The value the page renders.
    pub fn to_value(&self) -> Value {
        let name = self.name();
        match self {
            Refusal::Board(r) => json!({
                "kind": "refused",
                "name": name,
                "status": r.status,
                "code": r.code,
                "detail": r.detail,
                "op": r.op,
                "body": r.body,
            }),
            Refusal::Halt { face, .. } => json!({
                "kind": "halt",
                "name": name,
                "state": face.state,
                "cause": face.cause,
                "act": face.act,
            }),
            Refusal::Blocked(b) => json!({
                "kind": "blocked",
                "name": name,
                "record": b.record,
                "named_by": b.named_by,
                "ground": b.ground,
            }),
            Refusal::Unreachable(d) => json!({
                "kind": "unreachable",
                "name": name,
                "text": d.to_string(),
            }),
            Refusal::Shell { detail, .. } => {
                let mut out = Map::new();
                out.insert("kind".into(), Value::from("shell"));
                out.insert("name".into(), Value::from(name));
                if let Value::Object(members) = detail {
                    for (k, v) in members {
                        out.insert(k.clone(), v.clone());
                    }
                }
                Value::Object(out)
            }
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::Board(r) => write!(f, "{r}"),
            Refusal::Halt { name, face } => write!(f, "{name}: {face}"),
            Refusal::Blocked(b) => write!(f, "{b}"),
            Refusal::Unreachable(d) => write!(f, "unreachable: {d}"),
            Refusal::Shell { name, detail } => write!(f, "{name}: {detail}"),
        }
    }
}

impl From<Halt> for Refusal {
    fn from(h: Halt) -> Refusal {
        Refusal::of(h)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every member names ONE token: the board's key, the armed name, the
    /// block, the unreachable board, the shell's code — and renders under
    /// its kind with the member's own fields.
    #[test]
    fn every_refusal_names_one_token_and_renders_under_its_kind() {
        let board = Refusal::Board(Refused { status: 200, code: "credential_refused".into(), detail: Some("signed_session_required".into()), op: Some("publish".into()), body: json!({"resp": "rejected"}) });
        assert_eq!(board.name(), "signed_session_required");
        assert_eq!(board.to_value()["kind"], "refused");
        let plain = Refusal::Board(Refused { status: 503, code: "write_busy".into(), detail: None, op: None, body: Value::Null });
        assert_eq!(plain.name(), "write_busy");
        let face = Face { state: "s".into(), cause: "c".into(), act: "a".into() };
        let named = Refusal::named("no_key", face.clone());
        assert_eq!((named.name().as_str(), named.to_value()["state"].as_str()), ("no_key", Some("s")));
        assert_eq!(Refusal::of(Halt::Halt(face)).name(), "halt");
        let blocked = Refusal::Blocked(Blocked { record: "1.0.1.0.7.1".into(), named_by: "http://x".into(), ground: None });
        assert_eq!((blocked.name().as_str(), blocked.to_value()["record"].as_str()), ("blocked", Some("1.0.1.0.7.1")));
        let dial = Refusal::of(Halt::Dial(DialError::Connect("refused".into())));
        assert_eq!((dial.name().as_str(), dial.to_value()["kind"].as_str()), ("unreachable", Some("unreachable")));
        let shell = Refusal::shell(SESSION_ENDED, json!({"session": "s-1"}));
        let v = shell.to_value();
        assert_eq!((v["kind"].as_str(), v["name"].as_str(), v["session"].as_str()), (Some("shell"), Some("session_ended"), Some("s-1")));
    }
}
