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
//!   and `halt` where the row arms none;
//! * `blocked` — the handshake's `403 prefix_blocked` with its record and
//!   the ground read as a guest;
//! * `unreachable` — the board is not answering;
//! * `shell` — the shell's own refusal, with its detail.
//!
//! THE NAMES the shell spells — the shell's own refusals and the armed names
//! a halt's face takes — are [`Name`]'s constants and nothing else: its field
//! is private to this file, so a call site names a refusal only by a
//! constant declared here, and this list is the one the README and
//! `ARCHITECTURE.md` point to.

use std::fmt;

use serde_json::{json, Map, Value};
use skep_client::halt::{Blocked, Face, Halt, Refused};
use skep_client::DialError;

/// The refusal: the error every call answers, a `Halt` converting into its
/// member by `From`, so `?` carries a walk's halt to the row's refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The board's own verdict, verbatim.
    Board(Refused),
    /// A halt's face, under the armed name the row spells where one does.
    Halt { name: Name, face: Face },
    /// The block.
    Blocked(Blocked),
    /// The board is not answering.
    Unreachable(DialError),
    /// The shell's own refusal: its `detail` an object whose members ride
    /// beside `kind` and `name`, never in their place; a detail of another
    /// type renders no member.
    Shell { name: Name, detail: Value },
}

/// A NAME the shell spells: ONE token, closed to the constants below — the
/// shell's own refusals first, then the armed names a halt's face takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Name(&'static str);

impl Name {
    // ── THE SHELL's OWN: `Refusal::shell` ────────────────────────────────

    /// THE PIN's stale-reference refusal: "session ended" — a reference
    /// this shell holds no session under, issued or not.
    pub const SESSION_ENDED: Name = Name("session_ended");
    /// The call's session met the death signal: the reason its end carried
    /// beside it.
    pub const SESSION_DIED: Name = Name("session_died");
    /// A board reference this shell instance never issued.
    pub const UNKNOWN_BOARD: Name = Name("unknown_board");
    /// A call the bridge does not spell.
    pub const UNKNOWN_CALL: Name = Name("unknown_call");
    /// `fetch` through the dispatch: it streams, on its transport's own
    /// route.
    pub const STREAMED_CALL: Name = Name("streamed_call");
    /// A call's arguments are not the row's shape.
    pub const MALFORMED_ARGS: Name = Name("malformed_args");
    /// A row the library does not reach at this pin: the detail says where
    /// it stops.
    pub const NOT_REACHED: Name = Name("not_reached");
    /// A WRITE frame in the guest form, refused without a dial.
    pub const WRITE_IN_GUEST_FORM: Name = Name("write_in_guest_form");
    /// A guest form's origin is not a canonical origin.
    pub const NOT_CANONICAL: Name = Name("not_canonical");
    /// A query past the bridge's bound.
    pub const QUERY_TOO_LONG: Name = Name("query_too_long");
    /// The board's feed thread has stopped: no search is answered.
    pub const FEED_STOPPED: Name = Name("feed_stopped");
    /// The walk was abandoned: the page cancelled a moment, or the dev arm
    /// left.
    pub const ABANDONED: Name = Name("abandoned");
    /// A label refused as empty — `keygen`'s, and `accept`'s box as a
    /// halt's armed name.
    pub const EMPTY_LABEL: Name = Name("empty_label");
    /// A `select` that matches more than one key of the store.
    pub const AMBIGUOUS: Name = Name("ambiguous");
    /// A `select` that matches no key of the store.
    pub const NOT_FOUND: Name = Name("not_found");
    /// A claim on a board another store's claim stands on.
    pub const ALREADY_CLAIMED: Name = Name("already_claimed");
    /// `bind`'s pasted origin is not the board's.
    pub const ORIGIN_DISAGREES: Name = Name("origin_disagrees");
    /// `bind`'s pasted account and principal are not a pair the board
    /// seats.
    pub const ACCOUNT_DISAGREES: Name = Name("account_disagrees");
    /// `accept` with no address.
    pub const NO_ADDRESS: Name = Name("no_address");
    /// An attest asked of a session the board answered no account for.
    pub const NO_ACCOUNT: Name = Name("no_account");
    /// `held(session)`, and every act on the principal's held lines: the
    /// HELD-BURST store's file was written by a newer skep, or its body is
    /// damaged — the halt's face naming the path (PATTERNS P38; §3c.3).
    pub const STORE_HALTED: Name = Name("store_halted");
    /// `resolve(session, …)`: no held line of that ordinal stands.
    pub const NO_SUCH_HELD: Name = Name("no_such_held");
    /// `resolve(session, …)`: the line is `holding` or `sending`, not refused
    /// or moved — no act exists until the board answers (P10).
    pub const NOT_RESOLVABLE: Name = Name("not_resolvable");
    /// A burst whose frame passes the board's frame cap, as sent or as a
    /// resend's attest would carry it — one the board answers `413` unread at
    /// every send — refused at the act and never held.
    pub const FRAME_TOO_LARGE: Name = Name("frame_too_large");
    /// A burst the principal's held queue has no room for: its standing
    /// frames hold the queue's budget already — refused, and kept nowhere.
    pub const HELD_FULL: Name = Name("held_full");
    /// `answer(id, …)` or `cancel(id)` where no moment of that id waits.
    pub const NO_SUCH_MOMENT: Name = Name("no_such_moment");

    // ── THE HALTS' ARMED NAMES: `Refusal::named`, `Refusal::of_named` ────

    /// A halt the row arms no name for.
    pub const HALT: Name = Name("halt");
    /// The KEY store holds no key for (this board, the principal).
    pub const NO_KEY: Name = Name("no_key");
    /// The KEY store cannot be read — the shell's own data directory, its
    /// act and never a page act (`client.md` §4b.1).
    pub const STORE_UNREADABLE: Name = Name("store_unreadable");
    /// The KEY store cannot be written — the shell's own data directory, its
    /// act and never a page act (`client.md` §4b.1, §3.7).
    pub const STORE_UNWRITABLE: Name = Name("store_unwritable");
    /// The origin the shell signs for is not among the board's signed
    /// origins (AUTH-5.24, AUTH-5.36's origin state).
    pub const ORIGIN_STATE: Name = Name("origin_state");
    /// The principal holds no account at the board: `principal_prefix`
    /// answered none (AUTH-5.67 (2)).
    pub const NOT_REGISTERED: Name = Name("not_registered");
    /// The key stands in the retired list.
    pub const RETIRED: Name = Name("retired");
    /// The key stands in neither list.
    pub const NOT_ENROLLED: Name = Name("not_enrolled");
    /// The handshake halted after a pre-check that passed.
    pub const BUSY: Name = Name("busy");
    /// `accept` at an address that already holds a key set.
    pub const ALREADY_SEEDED: Name = Name("already_seeded");
    /// `accept` at an address not yet delegated.
    pub const NOT_DELEGATED: Name = Name("not_delegated");
    /// The attest a signed session's write needs could not be composed;
    /// nothing was sent.
    pub const ATTEST_NOT_COMPOSED: Name = Name("attest_not_composed");

    /// The token.
    pub fn as_str(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl Refusal {
    /// The shell's own refusal named `name`, with its detail object — its
    /// members rendered beside `kind` and `name`, never in their place.
    pub fn shell(name: Name, detail: Value) -> Refusal {
        Refusal::Shell { name, detail }
    }

    /// THE BOARD's VERDICT on a non-200 answer: its status, the error
    /// document's `error` as the code (`http_error` where the body names
    /// none), its `detail` and `op` where they ride, and the body whole —
    /// read as `skep-client` reads every non-200 it does not answer as a
    /// value.
    pub fn board(status: u16, body: Value) -> Refusal {
        Refusal::Board(Refused {
            status,
            code: body["error"].as_str().unwrap_or("http_error").to_string(),
            detail: body["detail"].as_str().map(str::to_string),
            op: body["op"].as_str().map(str::to_string),
            body,
        })
    }

    /// The row's arguments are not its shape: `what` says which member.
    pub fn malformed(what: impl Into<String>) -> Refusal {
        Refusal::shell(Name::MALFORMED_ARGS, json!({"what": what.into()}))
    }

    /// A halt the row arms no name for.
    pub fn halt(face: Face) -> Refusal {
        Refusal::Halt { name: Name::HALT, face }
    }

    /// A halt under the armed name the row spells.
    pub fn named(name: Name, face: Face) -> Refusal {
        Refusal::Halt { name, face }
    }

    /// The conversion `From<Halt>` makes, a halt's face taking `name`.
    pub fn of_named(name: Name, h: Halt) -> Refusal {
        match h {
            Halt::Halt(face) => Refusal::Halt { name, face },
            other => Refusal::from(other),
        }
    }

    /// The one token the page faces on.
    pub fn name(&self) -> &str {
        match self {
            Refusal::Board(r) => match (r.code.as_str(), r.detail.as_deref()) {
                ("credential_refused" | "registry_refused", Some(detail)) => detail,
                (code, _) => code,
            },
            Refusal::Halt { name, .. } | Refusal::Shell { name, .. } => name.as_str(),
            Refusal::Blocked(_) => "blocked",
            Refusal::Unreachable(_) => "unreachable",
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
                        out.entry(k.clone()).or_insert_with(|| v.clone());
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

impl std::error::Error for Refusal {}

/// The family's member as the row carries it: the board's verdict verbatim,
/// a halt's face under `halt`, the block, the unreachable board.
impl From<Halt> for Refusal {
    fn from(h: Halt) -> Refusal {
        match h {
            Halt::Refused(r) => Refusal::Board(r),
            Halt::Halt(face) => Refusal::halt(face),
            Halt::Blocked(b) => Refusal::Blocked(b),
            Halt::Dial(d) => Refusal::Unreachable(d),
        }
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
        let named = Refusal::named(Name::NO_KEY, face.clone());
        assert_eq!((named.name(), named.to_value()["state"].as_str()), ("no_key", Some("s")));
        assert_eq!(named.to_string(), format!("no_key: {face}"), "a halt renders as its name and its face");
        assert_eq!(Refusal::from(Halt::Halt(face)).name(), "halt");
        let blocked = Refusal::Blocked(Blocked { record: "1.0.1.0.7.1".into(), named_by: "http://x".into(), ground: None });
        assert_eq!((blocked.name(), blocked.to_value()["record"].as_str()), ("blocked", Some("1.0.1.0.7.1")));
        let dial = Refusal::from(Halt::Dial(DialError::Connect("refused".into())));
        assert_eq!((dial.name(), dial.to_value()["kind"].as_str()), ("unreachable", Some("unreachable")));
        let shell = Refusal::shell(Name::SESSION_ENDED, json!({"session": "s-1"}));
        let v = shell.to_value();
        assert_eq!((v["kind"].as_str(), v["name"].as_str(), v["session"].as_str()), (Some("shell"), Some("session_ended"), Some("s-1")));
    }

    /// A shell refusal's `kind` and `name` are its own, whatever its detail
    /// holds: a detail naming either rides beside them, never in their
    /// place, and a detail of no object renders no member.
    #[test]
    fn a_shell_refusals_detail_never_overwrites_its_token() {
        let v = Refusal::shell(Name::SESSION_ENDED, json!({"kind": "x", "name": "y", "session": "s-1"})).to_value();
        assert_eq!(v, json!({"kind": "shell", "name": "session_ended", "session": "s-1"}));
        assert_eq!(Refusal::shell(Name::SESSION_ENDED, json!("a string")).to_value(), json!({"kind": "shell", "name": "session_ended"}));
    }

    /// A non-200 is the board's verdict under its own status: the error its
    /// token, the members it carries kept in the body; a body that names no
    /// error is `http_error`.
    #[test]
    fn a_non_200_is_the_boards_verdict_under_its_status() {
        let r = Refusal::board(400, json!({"error": "beyond_head", "head": 12}));
        let v = r.to_value();
        assert_eq!((r.name(), v["kind"].as_str(), v["status"].as_u64(), v["body"]["head"].as_u64()), ("beyond_head", Some("refused"), Some(400), Some(12)));
        let named = Refusal::board(200, json!({"error": "credential_refused", "detail": "retired", "op": "publish"}));
        assert_eq!((named.name(), named.to_value()["op"].as_str()), ("retired", Some("publish")));
        assert_eq!(Refusal::board(502, Value::Null).name(), "http_error");
    }

    /// A VERDICT's NAME is the token its rejection dispatches on (wire.md
    /// §Rejections: "key client behavior on the token, never on prose"), the
    /// law over the families: `credential_refused` and `registry_refused`
    /// with a detail named by it, without one by their code, and any other
    /// code by itself, its detail prose (the mutant that drops a family from
    /// `name` faces `registry_refused` where the walk keys on its detail).
    #[test]
    fn a_verdicts_name_is_the_token_its_rejection_dispatches_on() {
        for code in ["credential_refused", "registry_refused", "out_of_bounds"] {
            for detail in [Some("a_token"), None] {
                let mut v = json!({"resp": "rejected", "code": code, "disposition": "permanent", "op": "insert"});
                if let Some(detail) = detail {
                    v["detail"] = json!(detail);
                }
                let r = skep_client::board::Rejection::of(&v).expect("a rejected document");
                assert_eq!(Refusal::from(r.refused(&v)).name(), r.key(), "{v}");
            }
        }
    }
}
