//! The one error family (`client.md` §1.1's `halt` row).
//!
//! `Halt` — a state a person must act on; `Refused` — the board's own
//! verdict, its token kept verbatim; `Blocked` — the handshake's `403
//! prefix_blocked`; `Dial` — transport. AUTH-5.66's one disposition rule
//! gives it its shape: every answer a client meets is an act it performs or
//! a halt it surfaces, never a retry, and the residue — every refusal no
//! state arms — is halt and surface. §2.3's exit codes are the binary's
//! mapping over this family ([`Halt::exit_code`]); the usage code, 2, is
//! the flag's shape alone and never a member here.

use std::fmt;

use serde_json::Value;

use crate::dial::DialError;

/// The family.
///
/// The variant named for the family is the halt-and-surface member: a state
/// a person must act on, faced as one block — the state, its cause as the
/// reads already made diagnose it, and the one act that clears it
/// (`client.md` §2.4) — and never a retry loop (AUTH-5.66).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Halt {
    /// Halt and surface — exit 3.
    Halt(Face),
    /// The board refused — exit 1, the token verbatim.
    ///
    /// The refusal is a `rejected` document, or a transport refusal: any
    /// status or `error` the exchange answers no other way, a
    /// `400 malformed_session_request` and a `413` among them.
    Refused(Refused),
    /// The handshake's `403 prefix_blocked` — exit 3.
    ///
    /// Halt and surface naming the block and the record address it carries
    /// (AUTH-5.25's blocked arm; AUTH-6.5), never a retry and never "busy".
    Blocked(Blocked),
    /// Transport — exit 4: the daemon unreachable, a timeout, a truncated body.
    ///
    /// It carries too an answer the wire does not give — a body that is not
    /// JSON, or one of a shape no read of this crate decodes.
    Dial(DialError),
}

/// A halt's one block (`client.md` §2.4).
///
/// The block is the state, its cause and the one act that clears it —
/// never a retry (AUTH-5.66), and where no act exists the face says so
/// plainly (P10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Face {
    /// What stands.
    pub state: String,
    /// Why, as diagnosed from the reads already made.
    pub cause: String,
    /// The one act that clears it — or that none exists.
    pub act: String,
}

/// The board's own verdict, the token kept verbatim.
///
/// It is a `rejected` document's `code` and `detail` in the `code:detail`
/// convention of the daemon's own suite (`auth_wire`), or a transport-level
/// refusal's `error` with its `detail` — a `400 malformed_session_request`,
/// a `413 payload_too_large`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    /// The HTTP status the verdict rode: 200 for a `rejected` document.
    pub status: u16,
    /// The `code` (a `rejected` document) or the `error` (a non-200).
    ///
    /// A non-200 that names no `error` carries `http_error`, this client's
    /// own token for it.
    pub code: String,
    /// The `detail`, where one rode.
    pub detail: Option<String>,
    /// The op the rejection answers, where a `rejected` document names one.
    pub op: Option<String>,
    /// The answer whole, for a face that renders more than the token.
    pub body: Value,
}

impl Refused {
    /// Returns the token in the `code:detail` convention.
    ///
    /// The token is `code` alone where no detail rode.
    pub fn token(&self) -> String {
        match &self.detail {
            Some(d) => format!("{}:{d}", self.code),
            None => self.code.clone(),
        }
    }
}

/// The handshake's `403 prefix_blocked` (AUTH-6.5; RES-65).
///
/// The account sits at or under a prefix the board's operator has listed,
/// the nonce is spent and no re-challenge is owed. It carries the one datum
/// the answer carries — the takedown record's version address — and the
/// ground read as a guest where it could be read, with its provenance
/// ("this board named this address; read at ⟨board⟩"), else that it could
/// not (RES-73). The face never names the lift, which is the operator's
/// alone (AUTH-4.57 (g)).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blocked {
    /// The takedown record's version address, as the refusal carried it.
    pub record: String,
    /// The board that named the address — the one dialed.
    pub named_by: String,
    /// The record's text as read at that board, where it could be read.
    ///
    /// It is `None` too where the walk reads no ground: the claim's bare
    /// binds and the hosted arm's take the block unread.
    pub ground: Option<String>,
}

/// Returns the longest prefix of `text` at most `max` bytes long.
///
/// The prefix ends on a character boundary — a board's text named in a face
/// without its whole length: a face is read by a person, and an answer may
/// run to megabytes.
pub(crate) fn clipped(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

impl Halt {
    /// Returns a halt-and-surface face from its three parts.
    pub fn face(state: impl Into<String>, cause: impl Into<String>, act: impl Into<String>) -> Halt {
        Halt::Halt(Face { state: state.into(), cause: cause.into(), act: act.into() })
    }

    /// Returns §2.3's exit code for this member of the family.
    ///
    /// The code is 3 for a halt and for the block, 1 for the board's
    /// refusal, 4 for transport.
    pub fn exit_code(&self) -> i32 {
        match self {
            Halt::Halt(_) | Halt::Blocked(_) => 3,
            Halt::Refused(_) => 1,
            Halt::Dial(_) => 4,
        }
    }
}

impl fmt::Display for Face {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}\n  cause: {}\n  act: {}", self.state, self.cause, self.act)
    }
}

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the board refused: {}", self.token())?;
        if let Some(op) = &self.op {
            write!(f, " (op {op})")?;
        }
        if self.status != 200 {
            write!(f, " (HTTP {})", self.status)?;
        }
        Ok(())
    }
}

impl fmt::Display for Blocked {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "this account is blocked at this board: the board named the takedown record {} \
             (prefix_blocked); the block stands until the board's operator lifts it",
            self.record
        )?;
        match &self.ground {
            Some(ground) => write!(
                f,
                "\n  ground: {ground}\n  provenance: this board ({}) named this address; read at {}",
                self.named_by, self.named_by
            ),
            None => write!(
                f,
                "\n  ground: the record at {} could not be read at {}, or does not answer for this account",
                self.record, self.named_by
            ),
        }
    }
}

impl fmt::Display for Halt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Halt::Halt(face) => write!(f, "{face}"),
            Halt::Refused(r) => write!(f, "{r}"),
            Halt::Blocked(b) => write!(f, "{b}"),
            Halt::Dial(d) => write!(f, "transport: {d}"),
        }
    }
}

impl std::error::Error for Halt {}

impl From<DialError> for Halt {
    fn from(e: DialError) -> Halt {
        Halt::Dial(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// §2.3's mapping over the family, and the token convention.
    #[test]
    fn the_exit_codes_and_the_token_convention() {
        assert_eq!(Halt::face("s", "c", "a").exit_code(), 3);
        let refused = Refused {
            status: 200,
            code: "credential_refused".into(),
            detail: Some("content_session".into()),
            op: Some("make_link".into()),
            body: Value::Null,
        };
        assert_eq!(refused.token(), "credential_refused:content_session");
        assert_eq!(Halt::Refused(refused).exit_code(), 1);
        let blocked = Blocked { record: "1.0.1.0.7.1".into(), named_by: "http://x".into(), ground: None };
        assert_eq!(Halt::Blocked(blocked).exit_code(), 3);
        assert_eq!(Halt::Dial(DialError::Connect("refused".into())).exit_code(), 4);
    }

    /// A board's text clipped for a face: whole where it fits.
    ///
    /// Else it is cut on the last character boundary at or before the bound.
    #[test]
    fn a_clipped_text_ends_on_a_character_boundary() {
        assert_eq!(clipped("1.0.1", 64), "1.0.1");
        assert_eq!(clipped(&"9".repeat(100), 64).len(), 64);
        assert_eq!(clipped("aé", 2), "a", "the two-byte é does not fit beside the a");
        assert_eq!(clipped("é", 0), "");
    }
}
