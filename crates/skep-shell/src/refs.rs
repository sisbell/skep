//! The reference registry's names (`client.md` §4b.1, the pin).
//!
//! A board reference and a session reference are opaque names the shell
//! issues — "a name, not a credential — it grants nothing by itself, every
//! `op` checked as untrusted as if it were absent; valid only inside this
//! shell instance, never derived from the token, never persisted by the
//! page; it dies with the token or the shell's restart". So a reference is
//! minted from OS entropy at the moment it is issued, carries nothing of
//! the origin or the token it stands for, and a reference this process
//! never issued matches nothing: the shell answers a board reference with
//! `unknown_board`, and a session reference with the pin's stale-reference
//! refusal, `session_ended` — or, where the reference names a session this
//! run ended, or one of another run of the shell, with `session_died` and
//! the reason (`shell`'s `session` lookup). For that a session reference
//! names THE RUN that minted it: each shell opened mints one run id
//! ([`run_id`], eight lowercase hex from OS entropy, held by its session
//! table), and a session reference is `s-`, the run's eight hex, `-` and
//! twenty-four lowercase hex of its own ([`session_reference`]), so a
//! shell that restarted under a page can tell a reference of its earlier
//! run from one it never issued ([`session_run`]; skep #625). A board
//! reference and a moment id carry no run: `b-` or `m-` and twenty-four
//! hex. The three kinds wear different prefixes, so a session reference
//! handed where a board's is expected matches nothing either. A board
//! reference names one board, its [`BoardEntry`]: minted with the entry,
//! and read beside its board whole.
//!
//! A fourth name never crosses the bridge: a held line's dial id
//! ([`DialId`]), `shell:` and twenty-four hex, the envelope `id` the hold
//! resends the line under (skep #971). Unlike the three it outlives the
//! process, kept with its line in the held file, since a resend after a
//! relaunch dials under the id the line's earlier resends did; and its
//! prefix is the shell's alone, refused as a page burst's `id` at the
//! burst's door, so no burst of a page's shares an `id` with a resend.

use std::fmt;
use std::sync::Arc;

use skep_client::sign::fresh_bytes;
use skep_client::Board;

/// The entropy in one reference or moment id, in bytes: ninety-six bits.
///
/// At that width two of one process never collide and none is ever guessed.
const REFERENCE_BYTES: usize = 12;

/// The entropy in a run id, in bytes: thirty-two bits, eight hex.
///
/// A run id tells one run of the shell from another under one page, never
/// a session from a session: two runs of one machine do not collide in
/// practice, and a collision costs a `session_ended` where `session_died`
/// was owed.
const RUN_BYTES: usize = 4;

/// One board of the shell, under the opaque reference minted for it.
///
/// The board is dialed through the shell's one dialer — its `dialed()` the
/// board's origin — and the reference is the name the page holds: the pair
/// the shell, the board's feed thread, its holds and every session that
/// stands at it read whole.
pub struct BoardEntry {
    pub reference: String,
    pub board: Arc<Board>,
}

impl BoardEntry {
    /// Returns the entry of `board` under a fresh board reference.
    pub fn new(board: Board) -> BoardEntry {
        BoardEntry { reference: board_reference(), board: Arc::new(board) }
    }
}

impl fmt::Debug for BoardEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BoardEntry({}, {})", self.reference, self.board.dialed())
    }
}

/// Returns a fresh board reference: `b-` and twenty-four lowercase hex.
///
/// It is minted for a [`BoardEntry`] alone.
fn board_reference() -> String {
    format!("b-{}", hex(&fresh_bytes(REFERENCE_BYTES)))
}

/// Returns a fresh run id: eight lowercase hex.
///
/// It is minted once per shell opened, by its session table, and names the
/// run in every session reference the table mints.
pub fn run_id() -> String {
    hex(&fresh_bytes(RUN_BYTES))
}

/// Returns a fresh session reference under `run`: `s-`, the run's eight
/// hex, `-`, and twenty-four lowercase hex.
pub fn session_reference(run: &str) -> String {
    format!("s-{run}-{}", hex(&fresh_bytes(REFERENCE_BYTES)))
}

/// Returns the run a well-formed session reference names.
///
/// It is the eight hex between the prefix and the reference's own
/// twenty-four, and `None` for a reference of any other form — the old
/// form's, a board reference, any text — which no run of the shell minted.
pub fn session_run(reference: &str) -> Option<&str> {
    let (run, own) = reference.strip_prefix("s-")?.split_once('-')?;
    (run.len() == 2 * RUN_BYTES && own.len() == 2 * REFERENCE_BYTES && is_hex(run) && is_hex(own)).then_some(run)
}

/// Returns a fresh moment id: `m-` and twenty-four lowercase hex.
///
/// It is the `id` a `moment` event carries and `answer`/`cancel` name.
pub fn moment_id() -> String {
    format!("m-{}", hex(&fresh_bytes(REFERENCE_BYTES)))
}

/// The prefix every dial id begins with, and no page burst's `id` may.
const DIAL_ID_PREFIX: &str = "shell:";

/// The most bytes a dial id adds to a frame as its `id` member.
///
/// It is the member `,"id":"…"` at a dial id's length: the room the burst's
/// door keeps within the board's frame cap for the `id` a resend carries.
pub const DIAL_ID_ROOM: usize = ",\"id\":\"\"".len() + DIAL_ID_PREFIX.len() + 2 * REFERENCE_BYTES;

/// The envelope `id` the hold resends a held line under (skep #971).
///
/// It is `shell:` and twenty-four lowercase hex from OS entropy, drawn once,
/// as the line is readied for its first resend, and kept with the line in
/// its held file, so every resend of the line dials under it, across the
/// shell's relaunches and a renumbering of the line alike. The board's
/// retry memo takes a frame for a reissue by its session, its `id` and its
/// kind (wire.md §Correlation and idempotency), so a resend under it is
/// answered the line's own acknowledgment or judged afresh, never handed
/// another line's. Made by [`DialId::fresh`] and, read back from a held
/// file, by [`DialId::parse`] alone (SP-18).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DialId(String);

impl DialId {
    /// Returns a fresh dial id: `shell:` and twenty-four lowercase hex.
    pub fn fresh() -> DialId {
        DialId(format!("{DIAL_ID_PREFIX}{}", hex(&fresh_bytes(REFERENCE_BYTES))))
    }

    /// Returns the dial id `text` spells, where it is of the form one takes.
    ///
    /// The form is the prefix and twenty-four lowercase hex, as
    /// [`DialId::fresh`] mints; any other text is no dial id.
    pub fn parse(text: &str) -> Option<DialId> {
        let own = text.strip_prefix(DIAL_ID_PREFIX)?;
        (own.len() == 2 * REFERENCE_BYTES && is_hex(own)).then(|| DialId(text.to_string()))
    }

    /// Returns the id as the wire and the held file spell it.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns whether a page's envelope `id` takes the dial ids' prefix.
    ///
    /// The burst's door refuses such an `id` (`hold`'s `Burst::admit`).
    pub fn reserves(id: &str) -> bool {
        id.starts_with(DIAL_ID_PREFIX)
    }
}

/// Returns the lowercase hex of `bytes`.
///
/// It is the one spelling every reference and moment id takes.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Returns whether `text` is lowercase hex throughout: the one spelling.
fn is_hex(text: &str) -> bool {
    text.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Checks that a reference or a moment id is a prefixed fresh hex string.
    ///
    /// A board reference and a moment id are their prefix and twenty-four
    /// lowercase hex; a session reference is `s-`, the run's eight hex, `-`
    /// and twenty-four of its own, and names its run; two differ; the three
    /// kinds wear three prefixes.
    #[test]
    fn a_reference_is_a_prefixed_fresh_hex_string() {
        let run = run_id();
        assert!(run.len() == 8 && is_hex(&run), "{run}");
        let (b, s, m) = (board_reference(), session_reference(&run), moment_id());
        for (minted, prefix) in [(&b, "b-"), (&m, "m-")] {
            assert!(minted.starts_with(prefix), "{minted}");
            let tail = &minted[2..];
            assert_eq!(tail.len(), 24, "{minted}");
            assert!(is_hex(tail), "{minted}");
        }
        assert!(s.starts_with(&format!("s-{run}-")), "{s}");
        let own = &s[11..];
        assert!(own.len() == 24 && is_hex(own), "{s}");
        assert_eq!(session_run(&s), Some(run.as_str()), "a session reference names its run");
        assert_ne!(board_reference(), b);
        assert_ne!(session_reference(&run), s);
        assert_ne!(run_id(), run);
        assert_eq!(hex(&[0x00, 0xab, 0xff]), "00abff");
    }

    /// Checks that a dial id is its prefix and fresh hex, and reads back alone.
    ///
    /// A fresh one is `shell:` and twenty-four lowercase hex and reads back as
    /// itself; two differ; text of any other form — the hex one short or one
    /// long, uppercase, the prefix in another case, a moment id — reads as
    /// none; the prefix is reserved whatever follows it, and nothing else is;
    /// and the room is the bytes a dial id's member adds to a frame.
    #[test]
    fn a_dial_id_is_its_prefix_and_fresh_hex_and_reads_back_alone() {
        let id = DialId::fresh();
        let own = id.as_str().strip_prefix("shell:").unwrap_or_else(|| panic!("{id:?}"));
        assert!(own.len() == 24 && is_hex(own), "{id:?}");
        assert_eq!(DialId::parse(id.as_str()), Some(id.clone()));
        assert_ne!(DialId::fresh(), id);
        let zeros = "0".repeat(24);
        let others =
            [format!("shell:{}", "0".repeat(23)), format!("shell:{zeros}0"), format!("shell:{}", "A".repeat(24)), format!("Shell:{zeros}"), format!("m-{zeros}"), "shell:".to_string(), String::new()];
        for text in others {
            assert_eq!(DialId::parse(&text), None, "{text}");
        }
        for (text, reserved) in [("shell:", true), ("shell:b-1", true), ("shellx", false), ("Shell:x", false), ("b-1", false)] {
            assert_eq!(DialId::reserves(text), reserved, "{text}");
        }
        let bytes = |frame: serde_json::Value| frame.to_string().len();
        assert_eq!(bytes(serde_json::json!({"op": "insert", "id": id.as_str()})) - bytes(serde_json::json!({"op": "insert"})), DIAL_ID_ROOM);
    }

    /// Checks that a reference of another form names no run.
    ///
    /// The old form (`s-` and twenty-four hex), a board reference, a run of
    /// the wrong width, uppercase hex, an own part of the wrong width and
    /// plain text each name none: a reference this run or another never
    /// minted is answered `session_ended`, never a death of another run.
    #[test]
    fn a_reference_of_another_form_names_no_run() {
        let own = "0".repeat(24);
        for text in [
            format!("s-{own}"),
            format!("b-{own}"),
            format!("s-0123456-{own}"),
            format!("s-012345678-{own}"),
            format!("s-0123ABCD-{own}"),
            format!("s-01234567-{}", "0".repeat(23)),
            format!("s-01234567-{own}x"),
            "s-gone".to_string(),
            String::new(),
        ] {
            assert_eq!(session_run(&text), None, "{text}");
        }
        assert_eq!(session_run(&format!("s-01234567-{own}")), Some("01234567"));
    }

    /// Checks that a board's entry takes a fresh board reference.
    ///
    /// The reference stands beside its board, so two entries over one origin
    /// take two: a reference names one entry, never its origin; the entry
    /// prints its reference and its board's origin.
    #[test]
    fn a_boards_entry_takes_a_fresh_reference_beside_its_board() {
        let origin = skep_client::Origin::parse("http://127.0.0.1:9").unwrap();
        let entry = || BoardEntry::new(Board::new(origin.clone(), skep_client::PlainHttp::new()));
        let (one, two) = (entry(), entry());
        assert!(one.reference.starts_with("b-") && one.reference != two.reference, "{} {}", one.reference, two.reference);
        assert_eq!((one.board.dialed(), two.board.dialed()), (&origin, &origin));
        assert_eq!(format!("{one:?}"), format!("BoardEntry({}, {origin})", one.reference));
    }
}
